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
