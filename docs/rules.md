# Detection Rules

Custom Wazuh rules written for this lab, stored in `configs/local_rules.xml`. All rules target Windows endpoint telemetry ingested via Sysmon and are mapped to MITRE ATT&CK techniques.

---

## Rule 100010 - Suspicious PowerShell Download (T1105)

**Description**
Detects process creation events where the command line contains native PowerShell download methods commonly used to retrieve payloads from remote infrastructure during the initial access or execution phase of an attack.

**Logic**

```xml
<rule id="100010" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(Invoke-WebRequest|iwr|Net\.WebClient|curl)</field>
  <description>Process creation w/ Suspicious PowerShell download</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>
```

**Data Sources**
- Sysmon Event ID 1 (Process Creation)

**Test Command**
```powershell
Invoke-AtomicTest T1105 -TestNumbers 10
```

**Expected Output**

| Field | Value |
|---|---|
| Rule ID | 100010 |
| Level | 14 (Critical) |
| Group | sysmon_event1, atomic_red_team |
| MITRE | T1105 - Ingress Tool Transfer |
| Alert visible in | Wazuh dashboard → Security Events |

**Tuning History**
- Added child suppression rule 100011 to eliminate persistent false positives from `MicrosoftEdgeUpdate.exe`, which uses `Invoke-WebRequest` internally during update checks.

**Automation Triggered**
This rule is tied to the Shuffle SOAR webhook integration. When it fires, the full automated pipeline executes: SHA256 hash extracted → Cortex queries VirusTotal → TheHive alert created → host isolated via `drop-firewall` if VirusTotal malicious count exceeds 3.

---

## Rule 100011 - Microsoft Edge Update Suppression

**Description**
Suppression rule that silences rule 100010 when the offending process is `MicrosoftEdgeUpdate.exe`. Edge's update mechanism uses the same PowerShell download patterns as the parent rule and would otherwise generate persistent false positives in any environment where Edge is installed.

**Logic**

```xml
<rule id="100011" level="0">
  <if_sid>100010</if_sid>
  <field name="win.eventdata.image">\\MicrosoftEdgeUpdate\.exe</field>
  <description>Suppression - False Positive from Microsoft Edge Update</description>
</rule>
```

**Data Sources**
- Sysmon Event ID 1 (Process Creation)

**Test Command**
Allow `MicrosoftEdgeUpdate.exe` to run naturally, or trigger rule 100010 via a process with `MicrosoftEdgeUpdate.exe` as the image path. Rule 100011 should fire at level 0, suppressing the alert.

**Expected Output**

| Field | Value |
|---|---|
| Rule ID | 100011 |
| Level | 0 (Suppressed) |
| Parent Rule | 100010 |
| Alert visible in | No alert generated |

**Tuning History**
- Initial version of rule 100010 produced high-frequency noise from Edge background processes. This suppression was added immediately during validation to keep the alert queue clean.

**Automation Triggered**
None. Level 0 rules do not trigger integrations or webhooks.

---

## Rule 100012 - Registry Run Key Modification (T1547.001)

**Description**
Detects registry value set events targeting `CurrentVersion\Run`, `RunOnce`, or `RunOnceEx` key paths under HKCU. Modification of these keys is a common persistence mechanism that causes attacker-controlled binaries to execute automatically on user login, without requiring elevated privileges.

**Logic**

```xml
<rule id="100012" level="13">
  <if_group>sysmon_event_13</if_group>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)HKU\\.*\\CurrentVersion\\Run(Once)?(EX)?</field>
  <description>Registry Run keys modified - Possible persistence mechanism</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
</rule>
```

**Data Sources**
- Sysmon Event ID 13 (Registry Value Set)

**Test Command**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**Expected Output**

| Field | Value |
|---|---|
| Rule ID | 100012 |
| Level | 13 (High) |
| Group | sysmon_event_13, atomic_red_team |
| MITRE | T1547.001 - Boot or Logon Autostart: Registry Run Keys |
| Alert visible in | Wazuh dashboard → Security Events |

**Tuning History**
No suppressions added. Legitimate software occasionally writes to Run keys during installation, so this rule warrants analyst review rather than automated response. The regex scope is limited to `HKU` (current user hive) to reduce noise from HKLM writes made by system processes during updates.

**Automation Triggered**
None in the current workflow. This rule is not bound to the Shuffle webhook integration. Alerts are visible in the Wazuh dashboard for manual analyst review.

---

## Rule 100013 - Scheduled Task Creation via Command Line (T1053.005)

**Description**
Detects process creation events where the command line contains scheduled task creation methods. Scheduled tasks created programmatically rather than through the Windows Task Scheduler GUI are a strong indicator of attacker-driven persistence or execution scheduling. Legitimate software installers occasionally create tasks this way, but it remains a high-value detection point.

**Logic**

```xml
<rule id="100013" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(schtasks.*\/create|New-ScheduledTask|Register-ScheduledTask)</field>
  <description>Suspicious Scheduled Task Creation via Command Line</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

**Data Sources**
- Sysmon Event ID 1 (Process Creation)

**Test Command**
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

**Expected Output**

| Field | Value |
|---|---|
| Rule ID | 100013 |
| Level | 12 (High) |
| Group | sysmon_event1, atomic_red_team |
| MITRE | T1053.005 - Scheduled Task/Job: Scheduled Task |
| Alert visible in | Wazuh dashboard → Security Events |

**Tuning History**
No suppressions added at this stage. Known false positive sources include software deployment tools and patch management agents. In a production environment, these would be suppressed by image path or parent process.

**Automation Triggered**
None in the current workflow. Alerts are visible in the Wazuh dashboard for manual analyst review.

---

## Sigma Conversion

All rules above have been converted to Sigma format for portability across SIEM platforms. The converted rules are stored in `configs/sigma_conversion.yaml`.
