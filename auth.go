package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var emailRe = regexp.MustCompile(`^[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,190}\.[a-z]{2,24}$`)

/* ---------- password hashing (PBKDF2-HMAC-SHA256, stdlib only) ---------- */

func pbkdf2Key(pass, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, pass)
	hLen := prf.Size()
	n := (keyLen + hLen - 1) / hLen
	var dk []byte
	for block := 1; block <= n; block++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

const pbkdfIter = 150000

func hashPass(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return "p1$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(pbkdf2Key([]byte(pw), salt, pbkdfIter, 32))
}

func checkPass(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != "p1" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(pbkdf2Key([]byte(pw), salt, pbkdfIter, 32), want) == 1
}

var dummyHash = hashPass("not-a-real-password")

/* ---------- sessions ---------- */

type session struct {
	uid string
	exp time.Time
}

var (
	sessMu   sync.Mutex
	sessions = map[string]session{}
	secretV  string
)

func serverSecret() string {
	if secretV != "" {
		return secretV
	}
	f := filepath.Join(dataDir, ".secret")
	syncDown("secret", f)
	if b, err := os.ReadFile(f); err == nil && len(b) >= 32 {
		secretV = strings.TrimSpace(string(b))
		pushLocal("secret", f)
		return secretV
	}
	secretV = newToken() + newToken()
	_ = os.WriteFile(f, []byte(secretV), 0600)
	syncUp("secret", []byte(secretV))
	return secretV
}

func startSession(w http.ResponseWriter, r *http.Request, uid string) {
	t := newToken()
	sessMu.Lock()
	for k, s := range sessions {
		if time.Now().After(s.exp) {
			delete(sessions, k)
		}
	}
	sessions[t] = session{uid: uid, exp: time.Now().Add(24 * time.Hour)}
	sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 86400, Secure: r.Header.Get("X-Forwarded-Proto") == "https"})
}

func revokeSessions(uid, keep string) {
	sessMu.Lock()
	for k, s := range sessions {
		if s.uid == uid && k != keep {
			delete(sessions, k)
		}
	}
	sessMu.Unlock()
}

func curUser(r *http.Request) (User, bool) {
	c, err := r.Cookie("sid")
	if err != nil {
		return User{}, false
	}
	sessMu.Lock()
	s, ok := sessions[c.Value]
	if ok && time.Now().After(s.exp) {
		delete(sessions, c.Value)
		ok = false
	}
	sessMu.Unlock()
	if !ok {
		return User{}, false
	}
	u, found := userByID(s.uid)
	if !found || u.Banned {
		return User{}, false
	}
	return u, true
}

func protect(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := curUser(r); !ok {
			jsonErr(w, 401, "login required")
			return
		}
		if !sameOrigin(r) {
			jsonErr(w, 403, "cross-site request blocked")
			return
		}
		h(w, r)
	}
}

func adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := curUser(r)
		if !ok {
			jsonErr(w, 401, "login required")
			return
		}
		if u.Role != "admin" {
			jsonErr(w, 403, "admin only")
			return
		}
		if !sameOrigin(r) {
			jsonErr(w, 403, "cross-site request blocked")
			return
		}
		h(w, r)
	}
}

/* ---------- OTP ---------- */

func genOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "123456"
	}
	return fmt.Sprintf("%06d", n.Int64())
}

func otpHash(email, code string) string {
	m := hmac.New(sha256.New, []byte(serverSecret()))
	m.Write([]byte(email + ":" + code))
	return hex.EncodeToString(m.Sum(nil))
}

// seconds left before another code may be sent: 30s after the first code, 60s after every resend
func otpCooldown(u User, now int64) int {
	if u.OTPSent == 0 {
		return 0
	}
	gap := int64(30)
	if u.OTPCount > 1 {
		gap = 60
	}
	if left := u.OTPSent + gap - now; left > 0 {
		return int(left)
	}
	return 0
}

func otpWaitFor(email string) int {
	if u, ok := userByEmail(email); ok {
		return otpCooldown(u, time.Now().Unix())
	}
	return 0
}

func issueOTP(uid, purpose string) error {
	code := genOTP()
	var email string
	var werr error
	store.with(func(d *Data) {
		for i := range d.Users {
			u := &d.Users[i]
			if u.ID != uid {
				continue
			}
			now := time.Now().Unix()
			if w := otpCooldown(*u, now); w > 0 {
				werr = fmt.Errorf("please wait %d seconds before requesting another code", w)
				return
			}
			u.OTPHash, u.OTPExp, u.OTPPurpose, u.OTPTries, u.OTPSent = otpHash(u.Email, code), now+600, purpose, 0, now
			u.OTPCount++
			email = u.Email
			return
		}
		werr = errors.New("user not found")
	})
	if werr != nil {
		return werr
	}
	if err := mailOTP(email, code, purpose); err != nil {
		return errors.New("could not send email: " + err.Error())
	}
	return nil
}

func checkOTP(email, code, purpose string) (User, error) {
	var res User
	var rerr error
	store.with(func(d *Data) {
		for i := range d.Users {
			u := &d.Users[i]
			if u.Email != email {
				continue
			}
			now := time.Now().Unix()
			if u.OTPHash == "" || u.OTPPurpose != purpose || now > u.OTPExp {
				rerr = errors.New("code expired — request a new one")
				return
			}
			if u.OTPTries >= 5 {
				rerr = errors.New("too many wrong codes — request a new one")
				return
			}
			if subtle.ConstantTimeCompare([]byte(otpHash(u.Email, strings.TrimSpace(code))), []byte(u.OTPHash)) != 1 {
				u.OTPTries++
				rerr = errors.New("wrong code")
				return
			}
			u.OTPHash, u.OTPExp, u.OTPPurpose, u.OTPTries, u.OTPCount = "", 0, "", 0, 0
			res = *u
			return
		}
		rerr = errors.New("wrong code")
	})
	return res, rerr
}

/* ---------- handlers ---------- */

func normEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func handleSignup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	email := normEmail(in.Email)
	if !emailRe.MatchString(email) {
		jsonErr(w, 400, "enter a valid email address")
		return
	}
	if len(in.Password) < 8 || len(in.Password) > 128 {
		jsonErr(w, 400, "password must be 8–128 characters")
		return
	}
	if !allow("signup:"+clientIP(r), 8, time.Hour) {
		jsonErr(w, 429, "too many sign-ups from your network — try later")
		return
	}
	ph := hashPass(in.Password)
	var uid string
	exists := false
	store.with(func(d *Data) {
		for i := range d.Users {
			u := &d.Users[i]
			if u.Email == email {
				if u.Verified {
					exists = true
					return
				}
				u.PassHash = ph
				uid = u.ID
				return
			}
		}
		u := User{ID: newToken()[:12], Email: email, PassHash: ph, Role: "user", Plan: "free", Created: time.Now().Unix()}
		d.Users = append(d.Users, u)
		uid = u.ID
	})
	if exists {
		jsonErr(w, 409, "this email is already registered — please log in")
		return
	}
	if err := issueOTP(uid, "verify"); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonOut(w, 200, map[string]any{"ok": true, "email": email, "wait": otpWaitFor(email)})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	u, err := checkOTP(normEmail(in.Email), in.Code, "verify")
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	updateUser(u.ID, func(x *User) { x.Verified = true; x.LastLogin = time.Now().Unix() })
	go mailWelcome(u.Email)
	startSession(w, r, u.ID)
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleResend(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	email := normEmail(in.Email)
	purpose := "verify"
	if in.Purpose == "reset" {
		purpose = "reset"
	}
	if wt := otpWaitFor(email); wt > 0 {
		jsonOut(w, 429, map[string]any{"error": fmt.Sprintf("please wait %d seconds before requesting another code", wt), "wait": wt})
		return
	}
	if !allow("otp:"+email, 6, time.Hour) || !allow("otpip:"+clientIP(r), 15, time.Hour) {
		jsonOut(w, 429, map[string]any{"error": "too many codes requested — try again in an hour", "wait": 3600})
		return
	}
	if u, ok := userByEmail(email); ok && !u.Banned && ((purpose == "verify" && !u.Verified) || (purpose == "reset" && u.Verified)) {
		if err := issueOTP(u.ID, purpose); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
	}
	jsonOut(w, 200, map[string]any{"ok": true, "wait": 60})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if lk, wait := locked(ip); lk {
		jsonErr(w, 429, lockMsg(wait))
		return
	}
	var in struct {
		ID   string `json:"id"`
		Pass string `json:"pass"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	u, ok := userByEmail(normEmail(in.ID))
	good := false
	if ok {
		good = checkPass(in.Pass, u.PassHash)
	} else {
		checkPass(in.Pass, dummyHash)
	}
	if !good {
		recordFail(ip)
		time.Sleep(600 * time.Millisecond)
		jsonErr(w, 401, "wrong email or password")
		return
	}
	if u.Banned {
		jsonErr(w, 403, "this account is suspended — contact support")
		return
	}
	recordOK(ip)
	if !u.Verified {
		_ = issueOTP(u.ID, "verify")
		jsonOut(w, 200, map[string]any{"needVerify": true, "email": u.Email, "wait": otpWaitFor(u.Email)})
		return
	}
	updateUser(u.ID, func(x *User) { x.LastLogin = time.Now().Unix() })
	startSession(w, r, u.ID)
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleForgot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	email := normEmail(in.Email)
	if !allow("forgot:"+clientIP(r), 6, time.Hour) || !allow("otp:"+email, 6, time.Hour) {
		jsonErr(w, 429, "too many requests — try again later")
		return
	}
	if u, ok := userByEmail(email); ok && u.Verified && !u.Banned {
		_ = issueOTP(u.ID, "reset")
	}
	jsonOut(w, 200, map[string]any{"ok": true, "wait": 30}) // same answer whether the email exists or not
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if jsonDecode(r, &in) != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	if len(in.Password) < 8 || len(in.Password) > 128 {
		jsonErr(w, 400, "password must be 8–128 characters")
		return
	}
	u, err := checkOTP(normEmail(in.Email), in.Code, "reset")
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	ph := hashPass(in.Password)
	updateUser(u.ID, func(x *User) { x.PassHash = ph })
	revokeSessions(u.ID, "")
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleChangePass(w http.ResponseWriter, r *http.Request) {
	u, _ := curUser(r)
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if jsonDecode(r, &in) != nil || len(in.New) < 8 || len(in.New) > 128 {
		jsonErr(w, 400, "new password must be 8–128 characters")
		return
	}
	if !checkPass(in.Old, u.PassHash) {
		jsonErr(w, 403, "current password is wrong")
		return
	}
	ph := hashPass(in.New)
	updateUser(u.ID, func(x *User) { x.PassHash = ph })
	keep := ""
	if c, err := r.Cookie("sid"); err == nil {
		keep = c.Value
	}
	revokeSessions(u.ID, keep)
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		sessMu.Lock()
		delete(sessions, c.Value)
		sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	jsonOut(w, 200, map[string]bool{"ok": true})
}

/* ---------- /api/me ---------- */

func allocOf(owner string) (int, float64, int) {
	ram, n := 0, 0
	cpu := 0.0
	for _, p := range store.projectsOf(owner) {
		ram += p.RAM
		cpu += p.CPU
		n++
	}
	return ram, cpu, n
}

func userDisk(owner string) int64 {
	var t int64
	for _, p := range store.projectsOf(owner) {
		t += dirSize(projDir(p))
	}
	return t
}

func dbCount(owner string) int {
	n := 0
	store.read(func(d *Data) {
		for _, x := range d.DBs {
			if x.Owner == owner {
				n++
			}
		}
	})
	return n
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := curUser(r)
	if !ok {
		jsonErr(w, 401, "login required")
		return
	}
	lim := limitsFor(u)
	ram, cpu, n := allocOf(u.ID)
	lr, lc := liveOf(u.ID)
	jsonOut(w, 200, map[string]any{
		"id": u.ID, "email": u.Email, "role": u.Role,
		"plan": activePlanID(u), "planName": lim.Name, "planUntil": u.PlanUntil, "autoRenew": u.AutoRenew,
		"limits":  lim,
		"usage":   map[string]any{"ram": ram, "cpu": cpu, "liveRam": lr, "liveCpu": lc, "disk": userDisk(u.ID) >> 20, "projects": n, "dbs": dbCount(u.ID)},
		"support": cfg().SupportURL,
	})
}
