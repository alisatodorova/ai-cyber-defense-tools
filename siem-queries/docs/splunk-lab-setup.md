# Splunk lab setup (native Windows) + BOTS dataset

Goal: a local Splunk Enterprise instance with realistic attack data (Splunk **BOTS v3**),
exposing the REST API on `https://localhost:8089` so the `/query` command works.

> This machine has no Docker/WSL, so we install Splunk **natively** as a Windows service.
> Same REST API, no containers, no reboots. Steps that need admin are marked **[admin]**.

---

## 1. Install Splunk Enterprise (native MSI) **[admin]**

winget only ships the Universal Forwarder, so grab the full server from Splunk:

1. Create a free account and download **Splunk Enterprise for Windows (64-bit `.msi`)**:
   https://www.splunk.com/en_us/download/splunk-enterprise.html
   (~1 GB. The free account is required by Splunk's download portal.)
2. Run the MSI **as Administrator**. During setup:
   - Choose an **admin username/password** (remember these — the script uses them once).
   - Let it install as a **Local System** Windows service (default).
3. After install, Splunk starts automatically. Verify:
   - Web UI: http://localhost:8000
   - REST API: https://localhost:8089 (self-signed cert — expected)

Default install path (`$SPLUNK_HOME`): `C:\Program Files\Splunk`

After the 60-day trial it converts to the **free license** automatically (500 MB/day ingest —
fine for a lab). You can also switch to the free license now under
*Settings → Licensing*.

---

## 2. Load the BOTS v3 dataset **[admin]**

BOTS (Boss of the SOC) v3 is a **data-only** Splunk app full of real attack telemetry
(Windows/Sysmon, Stream, AWS CloudTrail, etc.), well-suited to ATT&CK threat hunting.

1. Download `botsv3_data_set.tgz` from the official repo:
   https://github.com/splunk/botsv3  → the release/data link (~1 GB compressed).
2. Stop Splunk, extract the app into `etc\apps`, restart. In an **admin** PowerShell:

   ```powershell
   & "C:\Program Files\Splunk\bin\splunk.exe" stop
   # Extract the tgz so you end up with: C:\Program Files\Splunk\etc\apps\botsv3\
   tar -xzf "$HOME\Downloads\botsv3_data_set.tgz" -C "C:\Program Files\Splunk\etc\apps\"
   & "C:\Program Files\Splunk\bin\splunk.exe" start
   ```

3. Confirm the index loaded (Splunk Web → Search):
   ```spl
   | tstats count where index=botsv3 by sourcetype
   ```

### ⚠️ Critical gotcha: BOTS data is from **August 2018**

The events are historical, so a default `-24h` search returns **nothing**. When you run
`/query` against BOTS data, pass a wide timerange as the 2nd arg so it reaches back to 2018:

```
/query queries/lsass-access.txt -15y
```

`-15y` → now covers 2018. (Internally that becomes `earliest_time=-15y`, `latest_time=now`.)

---

## 3. Create a REST API token + set env vars

Once Splunk is running and you know the admin user/password, run the helper script
(no admin needed — it just talks to the REST API):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup-splunk-lab.ps1
```

> Use `powershell` (Windows PowerShell 5.1, built in). This machine has no `pwsh`
> (PowerShell 7). The script auto-detects the version and handles the self-signed
> cert either way. `-ExecutionPolicy Bypass` avoids a script-signing block.

It will:
- verify `https://localhost:8089` is reachable,
- enable token auth if needed and mint a token,
- set **`SPLUNK_HOST`** and **`SPLUNK_TOKEN`** as your *user* environment variables,
- run a smoke-test search against `index=botsv3`.

Open a **new** terminal afterwards so the env vars are present, then confirm:

```bash
echo "$SPLUNK_HOST"          # https://localhost:8089
# do NOT echo the token
```

---

## 4. Run your first investigation

```
/query queries/lsass-access.txt -15y
```

This reads the SPL from the file, runs it against Splunk, analyzes results, maps to
ATT&CK, and writes an Obsidian note to `investigations/`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `curl` cert error | Expected self-signed cert; the command already uses `-k`. |
| 401 Unauthorized | Token expired/rotated — re-run `scripts\setup-splunk-lab.ps1`. |
| 0 results on BOTS | You forgot the wide timerange — add `-15y` (data is from 2018). |
| Port 8089 refused | Splunk service not running: `& "C:\Program Files\Splunk\bin\splunk.exe" status`. |
| Token auth disabled | *Settings → Tokens → Enable*, or the script enables it via REST. |
