package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type User struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	PassHash   string `json:"passHash"`
	Role       string `json:"role"`
	Verified   bool   `json:"verified"`
	Banned     bool   `json:"banned"`
	Created    int64  `json:"created"`
	LastLogin  int64  `json:"lastLogin"`
	Plan       string `json:"plan"`
	PlanUntil  int64  `json:"planUntil"`
	AutoRenew  bool   `json:"autoRenew"`
	DiskMail   int64  `json:"diskMail,omitempty"`
	StripeCust string `json:"stripeCust,omitempty"`
	OTPHash    string `json:"otpHash,omitempty"`
	OTPExp     int64  `json:"otpExp,omitempty"`
	OTPPurpose string `json:"otpPurpose,omitempty"`
	OTPTries   int    `json:"otpTries,omitempty"`
	OTPSent    int64  `json:"otpSent,omitempty"`
	OTPCount   int    `json:"otpCount,omitempty"`
}

type Project struct {
	ID       string            `json:"id"`
	Owner    string            `json:"owner"`
	Name     string            `json:"name"`
	Runtime  string            `json:"runtime"`
	Detected string            `json:"detected,omitempty"`
	Cmd      string            `json:"cmd"`
	Port     int               `json:"port"`
	Inner    int               `json:"inner,omitempty"`
	RAM      int               `json:"ram"`
	CPU      float64           `json:"cpu"`
	Created  int64             `json:"created"`
	Repo     string            `json:"repo,omitempty"`
	Branch   string            `json:"branch,omitempty"`
	Token    string            `json:"token,omitempty"`
	Hook     string            `json:"hook,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	Sub      string            `json:"sub,omitempty"`
	Custom   []string          `json:"custom,omitempty"`
}

type DB struct {
	ID      string `json:"id"`
	Owner   string `json:"owner"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	URI     string `json:"uri"`
	Managed bool   `json:"managed"`
	Ident   string `json:"ident,omitempty"`
	Created int64  `json:"created"`
}

type Key struct {
	Code      string   `json:"code"`
	Plan      string   `json:"plan"`
	Months    int      `json:"months"`
	Note      string   `json:"note"`
	Created   int64    `json:"created"`
	UsedBy    string   `json:"usedBy,omitempty"`
	UsedAt    int64    `json:"usedAt,omitempty"`
	Uses      int      `json:"uses"` // how many different users may redeem it
	Used      []string `json:"used,omitempty"`
	ExpiresAt int64    `json:"expiresAt"` // 0 = never
}

type Payment struct {
	ID      string `json:"id"`
	UserID  string `json:"userId"`
	Email   string `json:"email"`
	Plan    string `json:"plan"`
	Months  int    `json:"months"`
	Amount  string `json:"amount"`
	Method  string `json:"method"`
	TxnID   string `json:"txnId"`
	Note    string `json:"note"`
	Status  string `json:"status"`
	Created int64  `json:"created"`
	Decided int64  `json:"decided"`
}

type Plan struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	RAM      int     `json:"ram"`  // MB
	CPU      float64 `json:"cpu"`  // cores
	Disk     int     `json:"disk"` // GB
	Price    float64 `json:"price"`
	Projects int     `json:"projects"`
	DBs      int     `json:"dbs"`
	Custom   bool    `json:"custom"`
}

type Data struct {
	Users    []User    `json:"users"`
	Projects []Project `json:"projects"`
	DBs      []DB      `json:"dbs"`
	Keys     []Key     `json:"keys"`
	Payments []Payment `json:"payments"`
	Plans    []Plan    `json:"plans"`
}

type Store struct {
	mu   sync.Mutex
	file string
	D    Data
}

var (
	store   *Store
	adminID string
)

func defaultPlans() []Plan {
	return []Plan{
		{ID: "free", Name: "Free", RAM: 256, CPU: 0.5, Disk: 1, Price: 0, Projects: 1, DBs: 1, Custom: false},
		{ID: "pro", Name: "Stark Pro", RAM: 4096, CPU: 2, Disk: 50, Price: 5, Projects: 20, DBs: 5, Custom: true},
		{ID: "max", Name: "Stark Max", RAM: 8192, CPU: 4, Disk: 100, Price: 9, Projects: 50, DBs: 15, Custom: true},
	}
}

func (s *Store) load() {
	syncDown("state", s.file) // MongoDB (if configured) is the source of truth
	b, err := os.ReadFile(s.file)
	if err == nil {
		_ = json.Unmarshal(b, &s.D)
	} else if lb, e := os.ReadFile(filepath.Join(filepath.Dir(s.file), "projects.json")); e == nil {
		_ = json.Unmarshal(lb, &s.D.Projects) // migrate old Nova Host projects
	}
	if len(s.D.Plans) == 0 {
		s.D.Plans = defaultPlans()
	}
	for i := range s.D.Projects {
		p := &s.D.Projects[i]
		if p.Sub == "" {
			p.Sub = randSub(p.Name)
		}
		if p.Hook == "" {
			p.Hook = newToken()[:20]
		}
		if p.Runtime == "" {
			p.Runtime = "auto"
		}
		if p.RAM <= 0 {
			p.RAM = 512
		}
		if p.CPU <= 0 {
			p.CPU = 0.5
		}
	}
	s.save()
}

func (s *Store) save() {
	b, _ := json.MarshalIndent(s.D, "", "  ")
	tmp := s.file + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, s.file)
	}
	syncUp("state", b)
}

// with: read+modify+save under lock.   read: read-only under lock.
func (s *Store) with(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.D)
	s.save()
}

func (s *Store) read(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.D)
}

/* ---------- users ---------- */

func userByID(id string) (User, bool) {
	var u User
	var ok bool
	store.read(func(d *Data) {
		for _, x := range d.Users {
			if x.ID == id {
				u, ok = x, true
				return
			}
		}
	})
	return u, ok
}

func userByEmail(email string) (User, bool) {
	var u User
	var ok bool
	store.read(func(d *Data) {
		for _, x := range d.Users {
			if x.Email == email {
				u, ok = x, true
				return
			}
		}
	})
	return u, ok
}

func updateUser(id string, fn func(*User)) {
	store.with(func(d *Data) {
		for i := range d.Users {
			if d.Users[i].ID == id {
				fn(&d.Users[i])
				return
			}
		}
	})
}

func planByID(id string) Plan {
	var out Plan
	store.read(func(d *Data) {
		for _, p := range d.Plans {
			if p.ID == id {
				out = p
				return
			}
		}
		for _, p := range d.Plans {
			if p.ID == "free" {
				out = p
				return
			}
		}
	})
	return out
}

func activePlanID(u User) string {
	grace := int64(0)
	if u.AutoRenew {
		grace = 2 * 86400 // renewal webhooks can arrive a little late
	}
	if u.Plan == "" || u.Plan == "free" || u.PlanUntil+grace < time.Now().Unix() {
		return "free"
	}
	return u.Plan
}

func limitsFor(u User) Plan {
	if u.Role == "admin" {
		ram, cpu, disk := vpsInfo()
		return Plan{ID: "admin", Name: "Admin (full VPS)", RAM: ram, CPU: cpu, Disk: disk, Projects: 1000, DBs: 1000, Custom: true}
	}
	return planByID(activePlanID(u))
}

/* ---------- projects ---------- */

func (s *Store) get(id string) (Project, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.D.Projects {
		if p.ID == id {
			return p, true
		}
	}
	return Project{}, false
}

func (s *Store) snapshot() []Project {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Project(nil), s.D.Projects...)
}

func (s *Store) projectsOf(owner string) []Project {
	var out []Project
	for _, p := range s.snapshot() {
		if p.Owner == owner {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) update(id string, fn func(*Project)) (Project, bool) {
	var out Project
	var ok bool
	s.with(func(d *Data) {
		for i := range d.Projects {
			if d.Projects[i].ID == id {
				fn(&d.Projects[i])
				out, ok = d.Projects[i], true
				return
			}
		}
	})
	return out, ok
}

func (s *Store) add(p Project) (Project, error) {
	var err error
	s.with(func(d *Data) {
		used := map[int]bool{}
		subs := map[string]bool{}
		for _, x := range d.Projects {
			if x.Name == p.Name {
				err = errors.New("this project name is already taken — choose another")
				return
			}
			used[x.Port] = true
			subs[x.Sub] = true
		}
		p.Port = 20000
		for used[p.Port] {
			p.Port++
		}
		p.Sub = randSub(p.Name)
		for subs[p.Sub] {
			p.Sub = randSub(p.Name)
		}
		d.Projects = append(d.Projects, p)
	})
	return p, err
}

func (s *Store) remove(id string) {
	s.with(func(d *Data) {
		kept := make([]Project, 0, len(d.Projects))
		for _, x := range d.Projects {
			if x.ID != id {
				kept = append(kept, x)
			}
		}
		d.Projects = kept
	})
}

func (s *Store) byHost(host string) (Project, bool) {
	base := baseDomain()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.D.Projects {
		if base != "" && host == p.Sub+"."+base {
			return p, true
		}
		for _, c := range p.Custom {
			if host == c {
				return p, true
			}
		}
	}
	return Project{}, false
}

/* ---------- global settings (admin editable) ---------- */

type Settings struct {
	BaseDomain       string `json:"baseDomain"`
	PublicIP         string `json:"publicIp"`
	SupportURL       string `json:"supportUrl"`
	Currency         string `json:"currency"`
	PayInstructions  string `json:"payInstructions"`
	SMTPHost         string `json:"smtpHost"`
	SMTPPort         string `json:"smtpPort"`
	SMTPUser         string `json:"smtpUser"`
	SMTPPass         string `json:"smtpPass"`
	SMTPFrom         string `json:"smtpFrom"`
	StripeSecret     string `json:"stripeSecret"`
	StripeWebhook    string `json:"stripeWebhook"`
	PayWebhookSecret string `json:"payWebhookSecret"`
	CryptoMerchant   string `json:"cryptoMerchant"`
	CryptoKey        string `json:"cryptoKey"`
}

var (
	setMu sync.RWMutex
	cfgS  Settings
)

func cfg() Settings {
	setMu.RLock()
	defer setMu.RUnlock()
	return cfgS
}

func settingsFile() string { return filepath.Join(dataDir, "settings.json") }

func loadSettings() {
	syncDown("settings", settingsFile())
	b, err := os.ReadFile(settingsFile())
	if err == nil {
		_ = json.Unmarshal(b, &cfgS)
	}
	if cfgS.SupportURL == "" {
		cfgS.SupportURL = "https://t.me/junaidaliniz"
	}
	if cfgS.Currency == "" {
		cfgS.Currency = "usd"
	}
	changed := false
	if cfgS.SMTPHost == "" && os.Getenv("SMTP_HOST") != "" {
		cfgS.SMTPHost, cfgS.SMTPPort = os.Getenv("SMTP_HOST"), env("SMTP_PORT", "587")
		cfgS.SMTPUser, cfgS.SMTPPass = os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS")
		cfgS.SMTPFrom = env("SMTP_FROM", os.Getenv("SMTP_USER"))
		changed = true
	}
	if cfgS.CryptoMerchant == "" && os.Getenv("CRYPTOMUS_MERCHANT") != "" {
		cfgS.CryptoMerchant, cfgS.CryptoKey = os.Getenv("CRYPTOMUS_MERCHANT"), os.Getenv("CRYPTOMUS_KEY")
		changed = true
	}
	if changed {
		saveSettings(cfgS)
	}
	if cfgS.PayWebhookSecret == "" {
		cfgS.PayWebhookSecret = newToken()
		saveSettings(cfgS)
	}
	pushLocal("settings", settingsFile())
}

func saveSettings(s Settings) {
	setMu.Lock()
	cfgS = s
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(settingsFile(), b, 0600)
	syncUp("settings", b)
	setMu.Unlock()
}
