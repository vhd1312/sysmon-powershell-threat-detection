# sysmon-powershell-threat-detection
Detection of suspicious PowerShell execution using Sysmon process creation telemetry, Python-based analysis, and MITRE ATT&amp;CK mapping




## Detection Workflow

### 1. Suspicious PowerShell Execution
The following commands were executed to generate Sysmon process creation events:

![PowerShell Command Execution](screenshots/command-run.png)

---

### 2. Detection Alerts
The Python detection script identifies suspicious PowerShell flags such as
`-ExecutionPolicy Bypass` and `-NoProfile`:

![Detection Alerts](screenshots/alert-output.png)

---

### 3. Detection Summary
The script also outputs a summary showing total events scanned and alerts generated:

![Detection Summary](screenshots/detection-summary.png)
