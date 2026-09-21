# Run it on your computer

## Open this in your browser

**http://127.0.0.1:5173**

(The API's own test page is http://127.0.0.1:8000/docs — you don't need it for the checklist.)

## Start (two PowerShell windows, in this order)

**Window 1 — backend**
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full\backend-developer
..\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```
Wait for `Application startup complete.`

**Window 2 — frontend**
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full\frontend-developer
npm install          # only the first time
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```
Wait for `Local: http://127.0.0.1:5173/`, then open http://127.0.0.1:5173.

## Stop
Press `Ctrl+C` in each window.

## If something is already using a port
```powershell
Get-NetTCPConnection -LocalPort 8000,5173 -ErrorAction SilentlyContinue | Select LocalPort,OwningProcess
Stop-Process -Id <the OwningProcess number> -Force
```

## 5-step checklist

1. **Engine is ready.** Top right says **● Analysis engine ready** (green dot). If it says *offline*, the backend window isn't running — start Window 1 and refresh the page.
2. **Upload.** Click the upload box and choose
   `E:\SIH\SIH_2026\SIH_2026_full\data\samples\aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap`,
   then click **Analyze capture**. Expected: the button shows *Analyzing...* for a second or two, then results appear.
3. **Check the results (strong config).** Expected:
   * risk gauge **100 / LOW**, with the note that it is *based on the configuration named in the file name*;
   * **Threat matrix**: Cipher, DH group and Mode in the *Low* column, **PFS in the grey *Unknown* column**;
   * **Handshake configuration**: `AES-GCM-16-128`, `tunnel`, `Group 19`, each with a yellow **from file name** badge;
   * **Traffic classification**: *Web browsing*, about 100 % confidence; **Traffic timeline** with about 14 one-second bars — hover a bar to see its time and confidence.
4. **Try the weak config and the toggle.** Upload
   `...\data\samples\aes128-dh2-transport-pfs-off__icmp_run1.pcap`.
   Expected: gauge **30 / HIGH**, DH group shown as *weak* (red), traffic = *ICMP (ping)*.
   Click the **Technical terms** switch (top right): the findings change to plain English.
   *(Also try a bad file — e.g. any `.txt` renamed to `.pcap`: you should see a red "Analysis failed … valid capture" message, not a crash.)*
5. **Download the PDF.** Click **Download report → Executive summary (PDF)**, then again **→ Technical report (PDF)**.
   Expected: two files appear in your Downloads folder (`...-executive.pdf`, `...-technical.pdf`). Open them:
   * executive: 2 pages, a coloured **risk box**, a settings table, **Recommended actions**, and a yellow box saying the values come from the file name;
   * technical: score arithmetic, IKE facts, traffic probabilities, a timeline chart, and a *Model validation* section.

**Also worth a glance:** the sample buttons under the upload box ("Or try a sample") run the same analysis without picking a file.
For the file-transfer sample the app deliberately shows *Low classification confidence* — it is a 300-packet excerpt, not a full capture.

## Automated version of this checklist
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full\frontend-developer; npm run build; cd ..
.\venv\Scripts\python.exe tools\e2e_check.py      # needs: pip install -r requirements-dev.txt
```
It starts its own servers on ports 8000/4173 — stop the ones above first.

---

## Share it with VS Code port forwarding

VS Code can publish your two local servers on the internet (a "Dev Tunnel") so someone else can open the site
in their browser. You share **one link: the forwarded 5173 address**. The site works out the forwarded 8000
address (the API) by itself, so nothing needs to be typed into the code.

### 1. Start the servers in "sharing mode" (replaces the two windows above)

**Window 1 — backend** (allows the forwarded addresses in CORS)
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full\backend-developer
$env:ALLOWED_ORIGINS = "http://127.0.0.1:5173,http://localhost:5173"
$env:ALLOWED_ORIGIN_REGEX = 'https://.*\.devtunnels\.ms|https://.*\.app\.github\.dev'
..\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**Window 2 — website** (a production build is steadier through a tunnel than the dev server)
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full\frontend-developer
npm run build
npm run preview -- --host 127.0.0.1 --port 5173 --strictPort
```
(Back to the live-reloading dev server later: stop this and run `npm run dev -- --host 127.0.0.1 --port 5173 --strictPort`.)

### 2. Forward the two ports in VS Code
1. Open the **Ports** tab (bottom panel; if you can't see it: menu **View → Terminal**, then the **PORTS** tab).
2. Click **Forward a Port**, type `8000`, press Enter. Do the same for `5173`.
   (VS Code may ask you to sign in with GitHub or Microsoft the first time.)
3. **Make both public, otherwise your friend must log in to your account:** right-click each row →
   **Port Visibility → Public**.
4. In the **Forwarded Address** column of the **5173** row you will see an address like
   `https://<random-name>-5173.<region>.devtunnels.ms`. **That is the link to share.**
   (The 8000 row looks the same with `-8000`; you do not share that one.)

### 3. Test it yourself first
Open the 5173 forwarded address in a **private/incognito window** (so you see what your friend sees).
* The first time, the tunnel may show a grey "Continue" warning page - click **Continue**.
* The top right must say **● Analysis engine ready**. Then follow the 5-step checklist above.
* Also open the **8000** forwarded address once and click **Continue** if a warning page appears (`.../health` should show `"status":"ok"`).

### If it says "Analysis engine offline"
* Both ports must be **Public** (step 2.3) and both servers must be running in sharing mode (step 1).
* Refresh after the servers start. Check the backend window for errors.
* Only if you want to force a specific API address: open `frontend-developer\.env.local` (git-ignored, local only),
  paste `VITE_API_URL=<the 8000 forwarded address>`, run `npm run build` again and restart the preview.
  **Never put that address in `.env`, `.env.example` or any committed file** - `.env.local` is never committed or deployed.

### Check it without a real tunnel
```powershell
cd E:\SIH\SIH_2026\SIH_2026_full
.\venv\Scripts\python.exe tools\tunnel_check.py     # servers must be running in sharing mode
```
It pretends the site is at a `...-5173...devtunnels.ms` address and checks, in a real browser, that the site finds the API,
that CORS passes and that a sample analysis and the PDF download work.
