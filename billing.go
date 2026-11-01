package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func applyPlan(uid, planID string, months int) error {
	var err error
	store.with(func(d *Data) {
		found := false
		for _, p := range d.Plans {
			if p.ID == planID && planID != "free" {
				found = true
			}
		}
		if !found {
			err = errors.New("unknown plan")
			return
		}
		for i := range d.Users {
			u := &d.Users[i]
			if u.ID != uid {
				continue
			}
			now := time.Now().Unix()
			base := now
			if u.Plan == planID && u.PlanUntil > now {
				base = u.PlanUntil
			}
			u.Plan = planID
			u.PlanUntil = base + int64(months)*30*86400
			return
		}
		err = errors.New("user not found")
	})
	return err
}

func addPayment(p Payment) string {
	p.ID = newToken()[:12]
	p.Created = time.Now().Unix()
	if p.Status != "pending" {
		p.Decided = p.Created
	}
	store.with(func(d *Data) { d.Payments = append(d.Payments, p) })
	return p.ID
}

// "your plan is active" email
func notifyPlan(uid, planID, paid, invoice string) {
	u, ok := userByID(uid)
	if !ok || !emailRe.MatchString(u.Email) {
		return
	}
	go mailOrder(u.Email, planByID(planID).Name, paid, invoice)
}

func txnSeen(txn string) bool {
	seen := false
	store.read(func(d *Data) {
		for _, p := range d.Payments {
			if p.TxnID == txn {
				seen = true
			}
		}
	})
	return seen
}

// stops a user's apps when their plan no longer covers what they use
func enforceQuota(uid string) int {
	if quotaErr(uid) == nil {
		return 0
	}
	n := 0
	for _, p := range store.projectsOf(uid) {
		if _, err := docker("stop", cname(p)); err == nil {
			n++
		}
	}
	return n
}

func planWatcher() {
	for {
		time.Sleep(5 * time.Minute)
		var ids []string
		store.read(func(d *Data) {
			for _, u := range d.Users {
				if u.Role != "admin" && u.Plan != "" && u.Plan != "free" && activePlanID(u) == "free" {
					ids = append(ids, u.ID)
				}
			}
		})
		for _, id := range ids {
			enforceQuota(id)
		}
		checkStorage()
	}
}

// emails a user once a day while their SSD is completely full
func checkStorage() {
	var users []User
	store.read(func(d *Data) { users = append(users, d.Users...) })
	for _, u := range users {
		if u.Role == "admin" || !u.Verified || u.Banned || !emailRe.MatchString(u.Email) {
			continue
		}
		lim := limitsFor(u)
		used := userDisk(u.ID)
		if used >= int64(lim.Disk)<<30 && time.Now().Unix()-u.DiskMail > 86400 {
			updateUser(u.ID, func(x *User) { x.DiskMail = time.Now().Unix() })
			go mailStorageFull(u, lim, used)
		}
	}
}

/* ---------- public plan list ---------- */

func handlePlans(w http.ResponseWriter, r *http.Request) {
	c := cfg()
	var pl []Plan
	store.read(func(d *Data) { pl = append(pl, d.Plans...) })
	jsonOut(w, 200, map[string]any{
		"plans": pl, "currency": strings.ToUpper(c.Currency), "stripe": c.StripeSecret != "",
		"manual": strings.TrimSpace(c.PayInstructions) != "", "crypto": c.CryptoMerchant != "" && c.CryptoKey != "", "instructions": c.PayInstructions, "support": c.SupportURL,
	})
}

func handlePlansGet(w http.ResponseWriter, r *http.Request) { handlePlans(w, r) }

/* ---------- license keys ---------- */

const keyAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func genKeyCode() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 20)
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, keyAlphabet[int(x)%len(keyAlphabet)])
	}
	return "STARK-" + string(out)
}

func handleRedeem(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	if !allow("redeem:"+u.ID, 10, time.Hour) {
		jsonErr(w, 429, "too many attempts — try again later")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	var key Key
	var rerr error
	store.with(func(d *Data) {
		for i := range d.Keys {
			k := &d.Keys[i]
			if k.Code != code {
				continue
			}
			if k.Uses <= 0 {
				k.Uses = 1
			}
			if len(k.Used) == 0 && k.UsedBy != "" {
				k.Used = []string{k.UsedBy}
			}
			now := time.Now().Unix()
			if k.ExpiresAt > 0 && now > k.ExpiresAt {
				rerr = errors.New("this key has expired")
				return
			}
			for _, x := range k.Used {
				if x == u.ID {
					rerr = errors.New("you already used this key")
					return
				}
			}
			if len(k.Used) >= k.Uses {
				rerr = errors.New("this key has reached its user limit")
				return
			}
			k.Used = append(k.Used, u.ID)
			k.UsedBy, k.UsedAt = u.ID, now
			key = *k
			return
		}
		rerr = errors.New("invalid key")
	})
	if rerr != nil {
		jsonErr(w, 400, rerr.Error())
		return
	}
	if err := applyPlan(u.ID, key.Plan, key.Months); err != nil {
		store.with(func(d *Data) {
			for i := range d.Keys {
				if d.Keys[i].Code == code {
					var keep []string
					for _, x := range d.Keys[i].Used {
						if x != u.ID {
							keep = append(keep, x)
						}
					}
					d.Keys[i].Used = keep
				}
			}
		})
		jsonErr(w, 400, err.Error())
		return
	}
	pid := addPayment(Payment{UserID: u.ID, Email: u.Email, Plan: key.Plan, Months: key.Months, Method: "key", TxnID: code, Status: "approved"})
	notifyPlan(u.ID, key.Plan, "Activated with key", pid)
	jsonOut(w, 200, map[string]any{"ok": true, "plan": key.Plan, "months": key.Months})
}

/* ---------- manual payment (Easypaisa / JazzCash / bank …) ---------- */

func handleHistory(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	out := []Payment{}
	store.read(func(d *Data) {
		for i := len(d.Payments) - 1; i >= 0; i-- {
			if d.Payments[i].UserID == u.ID && len(out) < 50 {
				out = append(out, d.Payments[i])
			}
		}
	})
	jsonOut(w, 200, out)
}

func handleManualPay(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	var in struct {
		Plan   string `json:"plan"`
		Months int    `json:"months"`
		Txn    string `json:"txn"`
		Note   string `json:"note"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	pl := planByID(in.Plan)
	if pl.ID != in.Plan || pl.ID == "free" {
		jsonErr(w, 400, "choose a paid plan")
		return
	}
	in.Txn = strings.TrimSpace(in.Txn)
	if len(in.Txn) < 4 || len(in.Txn) > 100 {
		jsonErr(w, 400, "enter the transaction ID of your payment")
		return
	}
	if in.Months < 1 || in.Months > 12 {
		in.Months = 1
	}
	if len(in.Note) > 300 {
		in.Note = in.Note[:300]
	}
	if txnSeen(in.Txn) {
		jsonErr(w, 409, "this transaction ID was already submitted")
		return
	}
	pending := 0
	store.read(func(d *Data) {
		for _, p := range d.Payments {
			if p.UserID == u.ID && p.Status == "pending" {
				pending++
			}
		}
	})
	if pending >= 3 {
		jsonErr(w, 429, "you already have 3 payments waiting for approval")
		return
	}
	amt := strconv.FormatFloat(pl.Price*float64(in.Months), 'f', 2, 64) + " " + strings.ToUpper(cfg().Currency)
	addPayment(Payment{UserID: u.ID, Email: u.Email, Plan: pl.ID, Months: in.Months, Amount: amt, Method: "manual", TxnID: in.Txn, Note: in.Note, Status: "pending"})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

/* ---------- Stripe (card, monthly auto-renew) ---------- */

func handleCheckout(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	c := cfg()
	if c.StripeSecret == "" {
		jsonErr(w, 400, "card payments are not enabled — use manual payment or a key")
		return
	}
	var in struct {
		Plan string `json:"plan"`
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
	scheme := "http"
	if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
		scheme = "https"
	}
	base := scheme + "://" + r.Host
	f := url.Values{}
	f.Set("mode", "subscription")
	f.Set("success_url", base+"/#/billing")
	f.Set("cancel_url", base+"/#/billing")
	f.Set("client_reference_id", u.ID)
	if strings.Contains(u.Email, "@") {
		f.Set("customer_email", u.Email)
	}
	f.Set("metadata[user]", u.ID)
	f.Set("metadata[plan]", pl.ID)
	f.Set("line_items[0][quantity]", "1")
	f.Set("line_items[0][price_data][currency]", strings.ToLower(c.Currency))
	f.Set("line_items[0][price_data][unit_amount]", strconv.FormatInt(int64(math.Round(pl.Price*100)), 10))
	f.Set("line_items[0][price_data][recurring][interval]", "month")
	f.Set("line_items[0][price_data][product_data][name]", "Stark-Host "+pl.Name+" (monthly)")
	req, _ := http.NewRequest("POST", "https://api.stripe.com/v1/checkout/sessions", strings.NewReader(f.Encode()))
	req.Header.Set("Authorization", "Bearer "+c.StripeSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		jsonErr(w, 502, "payment provider unreachable")
		return
	}
	defer resp.Body.Close()
	var out struct {
		URL   string `json:"url"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if out.URL == "" {
		msg := out.Error.Message
		if msg == "" {
			msg = "could not start checkout"
		}
		jsonErr(w, 502, msg)
		return
	}
	jsonOut(w, 200, map[string]string{"url": out.URL})
}

func stripeVerify(payload []byte, header, secret string) bool {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "t" {
			ts = kv[1]
		} else if kv[0] == "v1" {
			sigs = append(sigs, kv[1])
		}
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 || math.Abs(float64(time.Now().Unix()-t)) > 300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(payload)
	want := hex.EncodeToString(mac.Sum(nil))
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(want)) {
			return true
		}
	}
	return false
}

func userByStripe(cust string) (User, bool) {
	var u User
	var ok bool
	if cust == "" {
		return u, false
	}
	store.read(func(d *Data) {
		for _, x := range d.Users {
			if x.StripeCust == cust {
				u, ok = x, true
				return
			}
		}
	})
	return u, ok
}

func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	c := cfg()
	if c.StripeWebhook == "" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || !stripeVerify(body, r.Header.Get("Stripe-Signature"), c.StripeWebhook) {
		jsonErr(w, 400, "bad signature")
		return
	}
	var ev struct {
		Type string `json:"type"`
		Data struct {
			Object json.RawMessage `json:"object"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &ev) != nil {
		jsonErr(w, 400, "bad payload")
		return
	}
	switch ev.Type {
	case "checkout.session.completed":
		var s struct {
			ID            string            `json:"id"`
			Customer      string            `json:"customer"`
			ClientRef     string            `json:"client_reference_id"`
			Metadata      map[string]string `json:"metadata"`
			PaymentStatus string            `json:"payment_status"`
			AmountTotal   int64             `json:"amount_total"`
		}
		_ = json.Unmarshal(ev.Data.Object, &s)
		uid := s.Metadata["user"]
		if uid == "" {
			uid = s.ClientRef
		}
		if s.PaymentStatus == "paid" && uid != "" && !txnSeen(s.ID) {
			if applyPlan(uid, s.Metadata["plan"], 1) == nil {
				updateUser(uid, func(x *User) { x.StripeCust, x.AutoRenew = s.Customer, true })
				u, _ := userByID(uid)
				paid := moneySym(c.Currency) + strconv.FormatFloat(float64(s.AmountTotal)/100, 'f', 2, 64)
				pid := addPayment(Payment{UserID: uid, Email: u.Email, Plan: s.Metadata["plan"], Months: 1,
					Amount: strconv.FormatFloat(float64(s.AmountTotal)/100, 'f', 2, 64) + " " + strings.ToUpper(c.Currency), Method: "stripe", TxnID: s.ID, Status: "approved"})
				notifyPlan(uid, s.Metadata["plan"], paid, pid)
			}
		}
	case "invoice.paid":
		var inv struct {
			ID            string `json:"id"`
			Customer      string `json:"customer"`
			BillingReason string `json:"billing_reason"`
			AmountPaid    int64  `json:"amount_paid"`
		}
		_ = json.Unmarshal(ev.Data.Object, &inv)
		if inv.BillingReason == "subscription_cycle" && !txnSeen(inv.ID) {
			if u, ok := userByStripe(inv.Customer); ok && applyPlan(u.ID, u.Plan, 1) == nil {
				pid := addPayment(Payment{UserID: u.ID, Email: u.Email, Plan: u.Plan, Months: 1,
					Amount: strconv.FormatFloat(float64(inv.AmountPaid)/100, 'f', 2, 64) + " " + strings.ToUpper(c.Currency), Method: "stripe", TxnID: inv.ID, Status: "approved"})
				notifyPlan(u.ID, u.Plan, moneySym(c.Currency)+strconv.FormatFloat(float64(inv.AmountPaid)/100, 'f', 2, 64), pid)
			}
		}
	case "customer.subscription.deleted":
		var sub struct {
			Customer string `json:"customer"`
		}
		_ = json.Unmarshal(ev.Data.Object, &sub)
		if u, ok := userByStripe(sub.Customer); ok {
			updateUser(u.ID, func(x *User) { x.AutoRenew = false })
		}
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

/* ---------- generic payment webhook (any gateway / bot can call it) ---------- */

func handlePayWebhook(w http.ResponseWriter, r *http.Request) {
	c := cfg()
	sec := r.Header.Get("X-Webhook-Secret")
	if c.PayWebhookSecret == "" || subtle.ConstantTimeCompare([]byte(sec), []byte(c.PayWebhookSecret)) != 1 {
		jsonErr(w, 401, "invalid secret")
		return
	}
	var in struct {
		Email  string `json:"email"`
		Plan   string `json:"plan"`
		Months int    `json:"months"`
		Txn    string `json:"txn"`
		Amount string `json:"amount"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	if in.Months <= 0 {
		in.Months = 1
	}
	if in.Months > 24 {
		jsonErr(w, 400, "months too large")
		return
	}
	u, ok := userByEmail(normEmail(in.Email))
	if !ok {
		jsonErr(w, 404, "user not found")
		return
	}
	if in.Txn != "" && txnSeen(in.Txn) {
		jsonOut(w, 200, map[string]any{"ok": true, "duplicate": true})
		return
	}
	if err := applyPlan(u.ID, in.Plan, in.Months); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	pid := addPayment(Payment{UserID: u.ID, Email: u.Email, Plan: in.Plan, Months: in.Months, Amount: in.Amount, Method: "webhook", TxnID: in.Txn, Status: "approved"})
	paid := in.Amount
	if paid == "" {
		paid = "Paid"
	}
	notifyPlan(u.ID, in.Plan, paid, pid)
	jsonOut(w, 200, map[string]bool{"ok": true})
}
