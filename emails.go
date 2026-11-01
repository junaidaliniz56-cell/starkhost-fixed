package main

import (
	"embed"
	"fmt"
	"html"
	"strings"
)

//go:embed emails/*.html
var emailFS embed.FS

func renderEmail(name string, vars map[string]string) string {
	b, err := emailFS.ReadFile("emails/" + name + ".html")
	if err != nil {
		return ""
	}
	s := string(b)
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{"+k+"}", html.EscapeString(v))
	}
	return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:12px;background:#0a0203;">` + s + `</body></html>`
}

func userName(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}

func moneySym(cur string) string {
	switch strings.ToLower(cur) {
	case "usd":
		return "$"
	case "eur":
		return "€"
	case "gbp":
		return "£"
	case "inr":
		return "₹"
	case "pkr":
		return "Rs "
	}
	return strings.ToUpper(cur) + " "
}

func fmtBytes(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	}
	return fmt.Sprintf("%.0f MB", float64(n)/float64(1<<20))
}

func mailOTP(email, code, purpose string) error {
	tpl, subject := "verify", "Your StarkHost verification code"
	text := "Your StarkHost verification code is: " + code + "\n\nValid for 10 minutes. Never share this code. If you did not request it, ignore this email.\n\n— StarkHost (junaidnizaa.top)"
	if purpose == "reset" {
		tpl, subject = "reset", "Reset your StarkHost password"
		text = "Your StarkHost password reset code is: " + code + "\n\nValid for 10 minutes. If you did not request a reset, ignore this email.\n\n— StarkHost (junaidnizaa.top)"
	}
	return sendHTMLMail(email, subject, renderEmail(tpl, map[string]string{"username": userName(email), "otp_code": code}), text)
}

func mailWelcome(email string) {
	if !emailRe.MatchString(email) {
		return
	}
	_ = sendHTMLMail(email, "Welcome to StarkHost", renderEmail("welcome", map[string]string{"username": userName(email), "user_email": email}),
		"Welcome to StarkHost! Your account is verified. Open your dashboard: https://junaidnizaa.top:8443\n\n— StarkHost")
}

func mailOrder(email, planName, paid, invoice string) {
	_ = sendHTMLMail(email, "Your StarkHost plan is active", renderEmail("order", map[string]string{
		"username": userName(email), "plan_name": planName, "currency": "", "amount": paid, "invoice_id": invoice}),
		"Your StarkHost plan "+planName+" is now active ("+paid+", invoice #"+invoice+").\n\n— StarkHost")
}

func mailStorageFull(u User, lim Plan, used int64) {
	_ = sendHTMLMail(u.Email, "Your StarkHost storage is full", renderEmail("storage", map[string]string{
		"username": userName(u.Email), "used": fmtBytes(used), "limit": fmt.Sprintf("%d GB", lim.Disk), "plan_name": lim.Name}),
		"Your StarkHost account storage is full ("+fmtBytes(used)+" of "+fmt.Sprintf("%d GB", lim.Disk)+"). Aapke account ki memory full ho gayi hai. Free up space or upgrade: https://junaidnizaa.top:8443/#/billing\n\n— StarkHost")
}
