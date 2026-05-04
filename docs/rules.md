# Detection Rules

## Rule Index

| Rule ID | Name | MITRE | Level | Automation |
|---------|------|-------|-------|------------|
| [100010](#rule-100010--suspicious-powershell-download-t1105) | Suspicious PowerShell Download | T1105 | 14 | Shuffle SOAR pipeline |
| [100011](#rule-100011--microsoft-edge-update-suppression) | Microsoft Edge Update Suppression | N/A | 0 (Suppressed) | None |
| [100012](#rule-100012--registry-run-key-modification-t1547001) | Registry Run Key Modification | T1547.001 | 13 | None |
| [100013](#rule-100013--scheduled-task-creation-via-command-line-t1053005) | Scheduled Task Creation via CLI | T1053.005 | 12 | None |

---

## Rule 100010 - Suspicious PowerShell Download (T1105)

**Description:** Detects process creation events where the command line contains native PowerShell download methods commonly used to retrieve payloads during the initial access or execution phase of an attack.

**Data Source:**
- Sysmon Event ID 1 (Process Creation)

**Rule:**

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

**Test Command:**

```powershell
Invoke-AtomicTest T1105 -TestNumbers 10
```

**Expected Output:**

| Field | Value |
|-------|-------|
| Rule ID | 100010 |
| Level | 14 |
| Group | atomic_red_team |
| MITRE | T1105 |
| Alert visible in | Wazuh dashboard → Security Events |

**Tuning History**
- Added child suppression rule 100011 to eliminate persistent false positives from `MicrosoftEdgeUpdate.exe`. The Edge update process generates command line output containing the string `iwr` within an unrelated character sequence.

**Automation**
- Shuffle SOAR webhook integration. When fired: SHA256 hash extracted → Cortex queries VirusTotal → TheHive alert created → host isolated via `drop-firewall` if VirusTotal malicious count exceeds 3.

---

## Rule 100011 - Microsoft Edge Update Suppression

**Description:** Suppression rule for rule 100010 to eliminate false positives from `MicrosoftEdgeUpdate.exe`.

**Data Source:**
- Inherited from rule 100010 (Sysmon Event ID 1)

**Rule:**

```xml
<rule id="100011" level="0">
  <if_sid>100010</if_sid>
  <field name="win.eventdata.image">\\MicrosoftEdgeUpdate\.exe</field>
  <description>Suppression - False Positive from Microsoft Edge Update</description>
</rule>
```

**Test Command:**
- Validated by observing suppression during natural MicrosoftEdgeUpdate.exe activity. No synthetic test available.

**Expected Output:**

| Field | Value |
|-------|-------|
| Rule ID | 100011 |
| Level | 0 (Suppressed) |
| Parent Rule | 100010 |
| Alert visible in | No alert generated |

---

## Rule 100012 - Registry Run Key Modification (T1547.001)

**Description:** Detects registry value set events targeting `CurrentVersion\Run`, `RunOnce`, or `RunOnceEx` paths under HKCU. Modification of these keys is a common persistence mechanism that causes malicious binaries to execute automatically on user login without requiring elevated privileges.

**Data Source:**
- Sysmon Event ID 13 (Registry Value Set)

**Rule:**

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

**Test Command:**

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**Expected Output:**

| Field | Value |
|-------|-------|
| Rule ID | 100012 |
| Level | 13 |
| Group | atomic_red_team |
| MITRE | T1547.001 |
| Alert visible in | Wazuh dashboard → Security Events |

**Tuning History**
- No suppressions added. However, legitimate software occasionally writes to Run keys during installation.
- Regex scope is limited to `HKU` to reduce noise from HKLM writes made by system processes.

---

## Rule 100013 - Scheduled Task Creation via Command Line (T1053.005)

**Description:** Detects process creation events where the command line contains scheduled task creation methods. Scheduled tasks created via command line are a strong indicator of attacker-driven persistence or execution scheduling.

**Data Source:**
- Sysmon Event ID 1 (Process Creation)

**Rule:**

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

**Test Command:**

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

**Expected Output:**

| Field | Value |
|-------|-------|
| Rule ID | 100013 |
| Level | 12 |
| Group | atomic_red_team |
| MITRE | T1053.005 |
| Alert visible in | Wazuh dashboard → Security Events |

**Tuning History**
- No suppressions added. Known false positive sources include software deployment tools and patch management agents.
- Future suppressions would include image path or parent process.

---

## Sigma Conversion

All rules above have been converted to Sigma format, stored in [`configs/sigma_conversion.yaml`](../configs/sigma_conversion.yaml).
