"""
Sysmon PowerShell Threat Detection
Parses Sysmon Event ID 1 (Process Create) logs exported as XML
Detects suspicious PowerShell execution flags and maps to MITRE ATT&CK
"""


import xml.etree.ElementTree as ET

LOG_FILE = "sysmon.xml"

tree = ET.parse(LOG_FILE)
root = tree.getroot()

alerts = 0
events_seen = 0

for event in root.findall(".//{*}Event"):
    events_seen += 1

    image = ""
    cmd = ""
    parent = ""
    user = ""
    utc = ""

    for data in event.findall(".//{*}Data"):
        name = data.get("Name")
        value = (data.text or "").strip()

        if name == "Image":
            image = value
        elif name == "CommandLine":
            cmd = value
        elif name == "ParentImage":
            parent = value
        elif name == "User":
            user = value
        elif name == "UtcTime":
            utc = value
           
    cmd_l = cmd.lower()

    if "powershell.exe" in image.lower():
        if ("-executionpolicy bypass" in cmd_l) or ("-noprofile" in cmd_l):
            alerts += 1
            print("\n ALERT: Suspicious PowerShell Flags")
            print(f"UtcTime     : {utc or 'N/A'}")
            print(f"User        : {user or 'N/A'}")
            print(f"Image       : {image or 'N/A'}")
            print(f"ParentImage : {parent or 'N/A'}")
            print(f"CommandLine : {cmd or 'N/A'}")

        # Simple MITRE mapping
            print("MITRE       : T1059.001 (PowerShell)")
            if "-executionpolicy bypass" in cmd_l:
                print("Notes       : ExecutionPolicy Bypass (often used by attackers)")
            if "-noprofile" in cmd_l:
                print("Notes       : NoProfile (reduces artifacts / faster execution)")
            print("-" * 60)

print(f"\n[*] Done. Events scanned: {events_seen}, Total alerts: {alerts}")