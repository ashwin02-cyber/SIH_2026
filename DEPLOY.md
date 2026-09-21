# Deploying the IPsec VPN Analyzer — beginner guide

You will put **two things** on the internet:

| Part | What it is | Where (free) |
|---|---|---|
| **Website** (React) | what people see | **Vercel** (or Netlify) |
| **Server** (FastAPI) | analyses the uploaded capture | **Render** (or Railway) |

The website talks to the server, so you deploy the **server first**, then the website, then tell the server the website's address.
Everything below is done by clicking in a browser. Nothing here has been done for you: it needs *your* logins.

> **Before you start** you need: a GitHub account, the code pushed to GitHub (Step 0), and about 30 minutes.

---

## Step 0 — Put the code on GitHub

1. Open **PowerShell** and go to the project folder:
   ```powershell
   cd E:\SIH\SIH_2026\SIH_2026_full
   git status
   ```
   It should say `nothing to commit, working tree clean`.
2. Push the branch (this uploads your code; it is not done automatically):
   ```powershell
   git push -u origin finish-project
   ```
   GitHub may open a browser window asking you to sign in. Do that once.
3. On GitHub, open the repository `SIH_2026`, click the **branch dropdown** and check `finish-project` is there.
   (Optional: click **Compare & pull request** → **Create pull request** → **Merge** to put it on `main`.
   The steps below work with either branch — just pick the one you want when the sites ask.)

---

## Step 1 — Deploy the server on Render

1. Go to **https://render.com** → **Get Started** → **Sign in with GitHub** → allow access to the `SIH_2026` repository.
2. Click **New +** (top right) → **Blueprint**.
3. Pick the repository **SIH_2026**, choose the branch (`finish-project` or `main`), click **Connect**.
   Render reads the file `render.yaml` and shows a service called **ipsec-analyzer-api**.
4. Render asks for one value: **ALLOWED_ORIGINS**. Type `*` for now (you will make it stricter in Step 4). Click **Apply** / **Deploy Blueprint**.
5. Wait for the build (first time: **5–10 minutes**; it installs Python packages). The status turns **Live** (green).
6. Click the service name. At the top you see its address, like `https://ipsec-analyzer-api.onrender.com`. **Copy it.**
7. Test it: open `https://<your-address>/health` in a new tab. You must see:
   `{"status":"ok", ... "ml_model_loaded":true ...}`
   Also try `https://<your-address>/docs` — a page where you can upload a `.pcap` and click **Execute**.

**Good to know about Render's free plan**
* The server **falls asleep after ~15 minutes** without visitors. The next visit takes ~30–60 seconds to wake up. Open `/health` a minute before a demo.
* It has **512 MB of memory**. The app used about 320 MB in our test with a small capture, so keep uploads small (limit is set to 20 MB). If you see "out of memory" in the **Logs** tab, use a paid instance (Settings → Instance Type → Starter) or Railway.

### Alternative: Railway instead of Render
1. **https://railway.com** → **Login with GitHub** → **New Project** → **Deploy from GitHub repo** → pick `SIH_2026`.
2. Railway finds `railway.json` and builds with the Dockerfile automatically.
3. Open the service → **Settings** → **Networking** → **Generate Domain**. Copy the address and test `/health` as above.
4. **Variables** tab → **New Variable**: `ALLOWED_ORIGINS` = `*`, `MAX_UPLOAD_MB` = `20`.

---

## Step 2 — Deploy the website on Vercel

1. Go to **https://vercel.com** → **Sign Up** → **Continue with GitHub**.
2. Click **Add New…** → **Project** → find **SIH_2026** → **Import**.
3. On the configuration page:
   * **Root Directory**: click **Edit** → choose **`frontend-developer`** → **Continue**.
   * **Framework Preset**: should say **Vite** (the file `vercel.json` sets this).
   * Open **Environment Variables** and add:
     * **Name:** `VITE_API_URL`
     * **Value:** the Render address from Step 1 (e.g. `https://ipsec-analyzer-api.onrender.com`) — **no slash at the end**.
     * click **Add**.
4. Click **Deploy**. After ~1 minute you get a link like `https://sih-2026-xxxx.vercel.app`. **Copy it.**

> The address is baked into the website when it is built. If you change `VITE_API_URL` later, go to
> **Deployments** → the latest one → **⋯** → **Redeploy**.

### Alternative: Netlify instead of Vercel
1. **https://netlify.com** → **Sign up with GitHub** → **Add new site** → **Import an existing project** → **GitHub** → `SIH_2026`.
2. Netlify reads `netlify.toml` (base folder, build command, publish folder are pre-filled). Do not change them.
3. Click **Add environment variables** → key `VITE_API_URL`, value = your server address → **Deploy**.

---

## Step 3 — Try it

1. Open your Vercel (or Netlify) link. The top right should say **● Analysis engine ready** (green).
   *If it says "offline": wait 60 seconds (free server waking up) and refresh; if still offline see Troubleshooting.*
2. Click one of the sample buttons (e.g. `aes128gcm16-dh19-tunnel-pfs-on__web`) — the dashboard fills in.
3. Try **Download report → Executive summary (PDF)**.

## Step 4 — Lock the server to your website (recommended)

1. Render dashboard → your service → **Environment** → edit **ALLOWED_ORIGINS**.
2. Set it to your website address exactly, e.g. `https://sih-2026-xxxx.vercel.app` (no slash at the end; several addresses can be separated by commas).
3. **Save changes** — Render redeploys in a minute.

---

## Run everything on your own computer (optional)

Needs **Docker Desktop** running:
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full
docker compose up --build
```
Then open **http://localhost:8080** (website) and **http://localhost:8000/docs** (server). Stop with `Ctrl+C`.

Without Docker (two PowerShell windows):
```powershell
# window 1 - server
cd E:\SIH\SIH_2026\SIH_2026_full
.\venv\Scripts\Activate.ps1
cd backend-developer
uvicorn main:app --port 8000

# window 2 - website
cd E:\SIH\SIH_2026\SIH_2026_full\frontend-developer
npm install
npm run dev
```
Open the address `npm run dev` prints (usually http://localhost:5173).

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Website says **Analysis engine offline** | Open `<server address>/health` directly. If it loads, the website's `VITE_API_URL` is wrong or has a `/` at the end → fix it in Vercel and **Redeploy**. If it does not load, the free server is asleep — wait a minute — or it crashed: Render → **Logs**. |
| Browser console shows **CORS** error | `ALLOWED_ORIGINS` on the server does not match the website address exactly (https, no trailing slash). Set it to `*` to test, then to the exact address. |
| Render build fails with *out of memory / killed* | Free builds are limited. Retry once (**Manual Deploy → Clear build cache & deploy**), or use Railway. |
| Uploading a big file fails with **413** | The limit is `MAX_UPLOAD_MB` (20 on Render). Raise it only with a bigger instance. |
| "Not a valid capture file" | The file is not a real `.pcap`/`.pcapng` (e.g. renamed text file). |
| Reports fail | Check the server **Logs**; the report engine (xhtml2pdf) is part of the server image, so it also works offline from the website. |
| Score says "declared by the testbed" | Expected for the project's captures: they contain no readable IKE negotiation, so cipher/DH come from the file name. See `FINAL_STATUS.md`. |

## What is in the repo for deployment

| File | Used by |
|---|---|
| `render.yaml` | Render Blueprint (server) |
| `railway.json` | Railway (server) |
| `backend-developer/Dockerfile`, `requirements-backend.txt` | server image (Render, Railway, docker compose) |
| `frontend-developer/vercel.json` | Vercel (website) |
| `netlify.toml` | Netlify (website) |
| `frontend-developer/Dockerfile`, `nginx.conf` | website image (docker compose) |
| `docker-compose.yml` | run both locally |
| `frontend-developer/.env`, `.env.example` | local API address (`VITE_API_URL`) |
