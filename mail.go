package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"
)

func clean(s string) string { return strings.NewReplacer("\r", "", "\n", "").Replace(s) }

func b64wrap(s string) string {
	e := base64.StdEncoding.EncodeToString([]byte(s))
	var sb strings.Builder
	for len(e) > 76 {
		sb.WriteString(e[:76] + "\r\n")
		e = e[76:]
	}
	sb.WriteString(e + "\r\n")
	return sb.String()
}

func buildMsg(from, to, subject, htmlBody, text string) []byte {
	domain := "junaidnizaa.top"
	if i := strings.LastIndex(from, "@"); i >= 0 {
		domain = from[i+1:]
	}
	h := "From: StarkHost <" + from + ">\r\nTo: " + clean(to) + "\r\nSubject: " + clean(subject) +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMessage-ID: <" + newToken()[:24] + "@" + domain + ">\r\nMIME-Version: 1.0\r\nX-Auto-Response-Suppress: All\r\n"
	if htmlBody == "" {
		return []byte(h + "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64wrap(text))
	}
	bd := "stark" + newToken()[:20]
	return []byte(h + "Content-Type: multipart/alternative; boundary=\"" + bd + "\"\r\n\r\n" +
		"--" + bd + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64wrap(text) +
		"--" + bd + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64wrap(htmlBody) +
		"--" + bd + "--\r\n")
}

// plain-text mail (used by the admin "send test" button)
func sendMail(to, subject, body string) error { return sendHTMLMail(to, subject, "", body) }

// HTML mail with a plain-text alternative (better inbox placement than text only)
func sendHTMLMail(to, subject, htmlBody, text string) error {
	c := cfg()
	if c.SMTPHost == "" {
		log.Printf("[MAIL — SMTP not configured, printing instead] to=%s subject=%s\n%s", to, subject, text)
		return nil
	}
	from := clean(c.SMTPFrom)
	if from == "" {
		from = clean(c.SMTPUser)
	}
	if from == "" {
		return errors.New("SMTP From address is empty")
	}
	return smtpDeliver(c, from, to, buildMsg(from, to, subject, htmlBody, text))
}

func smtpDeliver(c Settings, from, to string, msg []byte) error {
	port := c.SMTPPort
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(c.SMTPHost, port)
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if port == "465" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: c.SMTPHost})
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
	cl, err := smtp.NewClient(conn, c.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if port != "465" {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(&tls.Config{ServerName: c.SMTPHost}); err != nil {
				return err
			}
		}
	}
	if c.SMTPUser != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.SMTPUser, c.SMTPPass, c.SMTPHost)); err != nil {
			return err
		}
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	if err := cl.Rcpt(to); err != nil {
		return err
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
