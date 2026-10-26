# DOJI TRADE — Demo-only project

## Features
- Node.js + Express + PostgreSQL
- Responsive dark demo trading UI
- Per-user simulated candle series and admin-only per-user manual OHLC controls
- TRC20-labelled deposit/withdrawal request UI, admin review and virtual demo balance updates
- User/account administration and demo trade history

## Important safety notes
- This is a simulation only. It does not accept or send real USDT, does not verify transactions on Tron, and displays no deposit wallet address. Never send crypto to this demo project.
- All candle values and trade outcomes are simulated, not live prices or predictions. Admin candle changes are isolated to the selected user's demo chart.
- Before any public deployment, set a strong random SESSION_SECRET, strong ADMIN_PASSWORD, use a managed PostgreSQL database, and review security/rate limiting/CSRF and applicable laws.

## Environment
Copy `.env.example` to `.env` and set:
- `DATABASE_URL` — PostgreSQL connection string
- `SESSION_SECRET` — long random secret
- `ADMIN_EMAIL` — initial admin email
- `ADMIN_PASSWORD` — strong initial admin password
- `NODE_ENV=production` for production cookie behavior

## Run locally
```bash
npm install
npm start
```
The server creates its tables on startup. On hosted deployments, configure environment variables in the hosting dashboard rather than committing `.env`.

## GitHub from Android
1. Download and extract this ZIP on your phone.
2. Open your repository in GitHub mobile browser.
3. Use **Add file → Upload files** (or GitHub Desktop alternative if the mobile UI hides it) and upload the extracted project files/folders, not the ZIP alone.
4. Do not upload `.env` or passwords. Commit the changes.
5. Connect the repository to a Node.js host and attach PostgreSQL; set environment variables in host settings, then deploy. A static host such as GitHub Pages/Netlify cannot run this Express backend by itself. Free hosting limits and database sleep/retention vary by provider.

## Demo admin
Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` before the first startup. If the database already has users but no admin, update the intended admin user's `role` to `admin` in PostgreSQL manually; never expose public admin registration.
