package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func cryptoSign(body []byte, key string) string {
	sum := md5.Sum([]byte(base64.StdEncoding.EncodeToString(body) + key))
	return hex.EncodeToString(sum[:])
}

func cryptoCall(path string, payload any) (map[string]any, error) {
	c := cfg()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	body := bytes.TrimSpace(buf.Bytes())
	req, err := http.NewRequest("POST", "https://api.cryptomus.com/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("merchant", c.CryptoMerchant)
	req.Header.Set("sign", cryptoSign(body, c.CryptoKey))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// POST /api/billing/crypto  {"plan":"pro","months":1}  ->  {"url": "https://pay.cryptomus.com/..."}
func handleCrypto(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	c := cfg()
	if c.CryptoMerchant == "" || c.CryptoKey == "" {
		jsonErr(w, 400, "crypto payments are not enabled yet")
		return
	}
	var in struct {
		Plan   string `json:"plan"`
		Months int    `json:"months"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	pl := planByID(in.Plan)
	if pl.ID != in.Plan || pl.ID == "free" || pl.Price <= 0 {
		jsonErr(w, 400, "choose a paid plan")
		return
	}
	if in.Months < 1 || in.Months > 12 {
		in.Months = 1
	}
	if !allow("crypto:"+u.ID, 10, time.Hour) {
		jsonErr(w, 429, "too many attempts — try later")
		return
	}
	amt := strconv.FormatFloat(pl.Price*float64(in.Months), 'f', 2, 64)
	cur := strings.ToUpper(c.Currency)
	pid := addPayment(Payment{UserID: u.ID, Email: u.Email, Plan: pl.ID, Months: in.Months, Amount: amt + " " + cur, Method: "cryptomus", Status: "pending"})
	scheme := "http"
	if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
		scheme = "https"
	}
	base := scheme + "://" + r.Host
	res, err := cryptoCall("payment", map[string]any{
		"amount": amt, "currency": cur, "order_id": pid, "lifetime": 3600,
		"url_callback": base + "/api/pay/cryptomus", "url_return": base + "/#/billing", "url_success": base + "/#/billing",
	})
	if err != nil {
		jsonErr(w, 502, "payment provider unreachable")
		return
	}
	rs, _ := res["result"].(map[string]any)
	link, _ := rs["url"].(string)
	uuid, _ := rs["uuid"].(string)
	if link == "" {
		msg, _ := res["message"].(string)
		if msg == "" {
			msg = "could not create the crypto invoice — check merchant ID and API key in Admin → Settings"
		}
		jsonErr(w, 502, msg)
		return
	}
	store.with(func(d *Data) {
		for i := range d.Payments {
			if d.Payments[i].ID == pid {
				d.Payments[i].TxnID = uuid
			}
		}
	})
	jsonOut(w, 200, map[string]string{"url": link})
}

// Cryptomus calls this when the invoice status changes. We never trust the body:
// we ask Cryptomus itself (signed request) whether the invoice is really paid.
func handleCryptoWebhook(w http.ResponseWriter, r *http.Request) {
	c := cfg()
	if c.CryptoMerchant == "" || c.CryptoKey == "" {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in struct {
		OrderID string `json:"order_id"`
	}
	if json.Unmarshal(body, &in) != nil || in.OrderID == "" {
		jsonErr(w, 400, "bad payload")
		return
	}
	res, err := cryptoCall("payment/info", map[string]any{"order_id": in.OrderID})
	if err != nil {
		jsonErr(w, 502, "could not verify")
		return
	}
	rs, _ := res["result"].(map[string]any)
	st, _ := rs["payment_status"].(string)
	switch st {
	case "paid", "paid_over":
		var pay Payment
		found := false
		store.with(func(d *Data) {
			for i := range d.Payments {
				p := &d.Payments[i]
				if p.ID == in.OrderID && p.Method == "cryptomus" && p.Status == "pending" {
					p.Status, p.Decided = "approved", time.Now().Unix()
					pay, found = *p, true
					return
				}
			}
		})
		if found && applyPlan(pay.UserID, pay.Plan, pay.Months) == nil {
			notifyPlan(pay.UserID, pay.Plan, pay.Amount, pay.ID)
		}
	case "cancel", "fail", "system_fail":
		store.with(func(d *Data) {
			for i := range d.Payments {
				p := &d.Payments[i]
				if p.ID == in.OrderID && p.Method == "cryptomus" && p.Status == "pending" {
					p.Status, p.Decided = "rejected", time.Now().Unix()
				}
			}
		})
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
