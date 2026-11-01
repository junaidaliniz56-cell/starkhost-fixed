# StarkHost

Public hosting platform: sign-up with email OTP, plans (Free / Pro / Max), license keys, payments, admin panel,
per-user RAM / CPU / SSD limits, free + custom domains with HTTPS, file editor, live logs, GitHub auto-deploy
and built-in MongoDB / PostgreSQL / MySQL.

## Install (fresh VPS with Docker; 2 GB RAM minimum, more if you run all databases)
```bash
mkdir -p /srv/hosting
nano .env                        # set PANEL_DOMAIN (+ optional BASE_DOMAIN); ADMIN_PASS is already set
docker compose --profile dbs up -d --build      # panel + HTTPS + MongoDB + PostgreSQL + MySQL
# only panel:   docker compose up -d --build
```
No Docker Compose? Start the panel and the built-in databases directly:
```bash
sh run.sh          # panel
sh start-dbs.sh    # PostgreSQL + MongoDB + MySQL (safe to run again)
```

Open `https://your-domain` (or `http://SERVER-IP`). Log in as `admin` (password in `.env`).

## First things to do in Admin → Settings
1. **Email (SMTP)** — needed for OTP codes (Gmail: smtp.gmail.com, port 587, app-password; or Brevo / Zoho / Mailgun). Use "Send test".
   Without SMTP the codes only appear in `docker compose logs panel`.
2. **Payments** — manual instructions (Easypaisa / JazzCash / bank), Stripe keys (card + monthly auto-renew), or the
   generic **auto-payment webhook** (any gateway/bot POSTs `{email, plan, months, txn}` with the secret).
3. **Plans** — change RAM / CPU / SSD / price / limits.
4. **Keys** — plan + months + members (how many users can use one key) + expiry days. Users redeem under "Redeem Key".
5. **Check a user's bot/script** — Admin → All projects → Files / Logs / ⬇ ZIP.

## Domains
* Panel: set `PANEL_DOMAIN`, point its A record to the server IP.
* User apps: free `name-xxxx.<ip>.sslip.io` works instantly. For your own domain set `BASE_DOMAIN=starkapps.net` and add a
  wildcard A record `*.starkapps.net`. **Use a different domain for apps than for the panel** (safer).
* Paid users can add their own custom domains (A record → server IP); HTTPS is automatic.

## Security — please read
* Every app runs in its own container with RAM / CPU limits, dropped capabilities, no privileged mode, and a private
  network per user. Still: **running other people's code is risky.** Use a dedicated VPS, keep it updated, firewall only 22/80/443.
* The panel controls Docker (full server access) — keep the admin password strong, never share `.env`.
* Monitor abuse (crypto-miners, spam): Admin → All projects lets you stop / delete anything; Users → Ban.
* Back up `/srv/hosting` (state.json, projects, databases).

❤️ Developer By Junaid-Niz 💔 — https://github.com/junaidaliniz56-cell/starkhost

## Domain & email (junaidnizaa.top)
* `.env` → `PANEL_DOMAIN=junaidnizaa.top`, DNS: **A** record `junaidnizaa.top` (and `www`) → server IP. HTTPS is automatic.
* **OTP mails going to spam?** Use a real sender on your own domain, not a free Gmail address:
  1. Brevo (or Zoho / Mailgun / SES) → add domain **junaidnizaa.top** and add the DNS records they show: **SPF**, **DKIM** (and a **DMARC** TXT record: `v=DMARC1; p=none; rua=mailto:you@junaidnizaa.top`).
  2. Admin → Settings → From address = `no-reply@junaidnizaa.top` (must be on that verified domain).
  3. While the domain is new, press "Report not spam" on your own test mails a few times; reputation builds with time.
* Emails are HTML + plain text (verification, password reset, welcome, plan activated, storage full).
* Storage warning: at 90% a banner shows in the dashboard; at 100% the user gets the "storage full" email (max once a day).

## Cryptomus (crypto payments)
Admin → Settings → Payments: enter **Merchant ID** and **Payment API key** (Cryptomus → Merchant → Settings). The callback URL is set automatically
(`https://junaidnizaa.top/api/pay/cryptomus`). After the user pays, the server asks Cryptomus to confirm the invoice and turns the plan on by itself.

## Keep accounts after every update (MongoDB)
Put your MongoDB Atlas URI in `.env` as `MONGO_URI` (and the password in `MONGO_URI_PASSWORD` if the URI has `<db_password>`).
If `MONGO_URI` is empty, the existing `ADMIN_DB_MONGO` is used. Accounts, projects, plans, keys, payments, settings and the
session secret are then saved in database `starkhost_panel` (collection `panel_data`) and loaded again at every start,
so redeploys/updates/disk wipes never delete accounts. Old local data is uploaded automatically the first time.
In Atlas → Network Access allow your server IP (or 0.0.0.0/0). If MongoDB cannot be reached the panel stops and retries
(instead of creating accounts that would be lost) — check `docker compose logs panel`.
