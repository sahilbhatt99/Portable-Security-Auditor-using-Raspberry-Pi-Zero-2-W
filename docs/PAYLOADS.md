================================================================================
  PORTABLE SECURITY AUDITOR - PAYLOAD REFERENCE GUIDE
  Raspberry Pi Zero 2 W | USB HID Injection System
================================================================================
  Total Payloads : 20
  Last Updated   : 2026-04-15
  Author         : Sahil Bhatt (@sahilbhatt99)
================================================================================

Each payload is a .bat file served by the Pi over HTTP. When executed, the HID
system injects keystrokes to open an elevated PowerShell on the target Windows
machine, downloads the .bat file, runs it silently, then uploads the output
file(s) back to the Pi via POST request on port 8000.

Elevation method: WIN+R -> powershell -> CTRL+SHIFT+ENTER -> ALT+Y (UAC bypass)

--------------------------------------------------------------------------------
  HOW TO USE
--------------------------------------------------------------------------------
  1. Start the Pi server (./run.sh)
  2. Plug Pi into target Windows PC via USB
  3. Open dashboard: http://172.16.0.1
  4. Set scan metadata (device, owner, scan number)
  5. Enable HID system
  6. Select a payload from the dropdown and click Execute
  7. Wait for live log to confirm completion
  8. Collected files appear in: uploads/YYYYMMDD_HHMMSS_scanN_device_owner/

--------------------------------------------------------------------------------
  SECTION 1 — UTILITY PAYLOADS
--------------------------------------------------------------------------------

[1] test
  File        : test.bat
  Description : Opens Notepad with a test message.
  Purpose     : Verify the HID injection pipeline is working end-to-end before
                running real audit payloads. No data is collected or uploaded.
  Output      : None
  Elevation   : No
  Compatibility: All Windows versions

--------------------------------------------------------------------------------

[2] sysinfo
  File        : sysinfo.bat
  Description : Collects basic Windows system information.
  Purpose     : Gathers hostname, username, OS name/version, architecture, and
                system uptime for initial device fingerprinting.
  Output      : audit_sysinfo.json
  Elevation   : No
  Compatibility: All Windows versions

--------------------------------------------------------------------------------

[3] compliance
  File        : compliance.bat
  Description : Quick compliance check — verifies key security baselines.
  Purpose     : Checks whether basic security hygiene settings are in place
                (e.g., defender status, firewall state, UAC level) and reports
                pass/fail results in JSON format.
  Output      : audit_compliance.json
  Elevation   : Recommended
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------
  SECTION 2 — REGISTRY EXPORT PAYLOADS
--------------------------------------------------------------------------------

[4] export_policies
  File        : export_policies.bat
  Description : Exports HKLM\Software\Policies registry hive.
  Purpose     : Captures machine-wide Group Policy and software restriction
                settings applied at the system level. Shows enforced security
                policies for all users on the machine.
  Output      : audit_hklm_policies.txt
  Elevation   : Required (HKLM access)
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------

[5] export_user_policies
  File        : export_user_policies.bat
  Description : Exports HKCU\Software\Policies registry hive.
  Purpose     : Captures user-specific Group Policy settings applied to the
                currently logged-in user. Useful for per-user policy analysis.
  Output      : audit_hkcu_policies.txt
  Elevation   : No (HKCU access only)
  Compatibility: All Windows versions

--------------------------------------------------------------------------------

[6] export_registry_hkcu
  File        : export_registry_hkcu.bat
  Description : Deep queries HKCU\Software\Policies using reg query /s.
  Purpose     : Shows the ACTUAL ENFORCED state of user policies at runtime,
                including all sub-keys and values. More granular than a reg
                export — reveals what is actively applied vs just defined.
                Useful for: forensics, policy debugging, compliance auditing.
  Output      : audit_hkcu_registry.txt
  Elevation   : No
  Compatibility: All Windows versions

--------------------------------------------------------------------------------

[7] export_services
  File        : export_services.bat
  Description : Exports HKLM\SYSTEM\CurrentControlSet\Services registry hive.
  Purpose     : Captures all registered Windows services including third-party
                ones. Used to detect unquoted service paths, suspicious services,
                and privilege escalation vectors.
  Output      : audit_services.txt
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------

[8] export_control
  File        : export_control.bat
  Description : Exports HKLM\SYSTEM\CurrentControlSet\Control registry hive.
  Purpose     : Captures low-level system control settings: session manager,
                LSA configuration, boot configuration, and hardware control.
                Useful for detecting LSA protections, secure boot state, and
                credential guard configuration.
  Output      : audit_control.txt
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------
  SECTION 3 — SECURITY CONFIGURATION PAYLOADS
--------------------------------------------------------------------------------

[9] export_firewall
  File        : export_firewall.bat
  Description : Dumps all Windows Firewall rules.
  Purpose     : Lists every inbound and outbound firewall rule with its name,
                direction, action, protocol, ports, and enabled state. Used to
                identify over-permissive rules, disabled protections, or
                backdoor rules added by malware.
  Output      : audit_firewall.txt
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------

[10] export_defender
  File        : export_defender.bat
  Description : Exports Windows Defender / Microsoft Defender preferences.
  Purpose     : Captures all Defender configuration settings including real-time
                protection state, exclusions, scan schedules, cloud protection
                level, and tamper protection state. Exclusions are a common
                persistence/evasion technique.
  Output      : audit_defender.json
  Elevation   : Required
  Compatibility: Windows 10/11 (Defender must be active)

--------------------------------------------------------------------------------

[11] export_secedit
  File        : export_secedit.bat
  Description : Exports the local security policy via secedit.
  Purpose     : Extracts the full local security configuration including:
                  - Account Policies (password length, complexity, lockout)
                  - User Rights Assignments (who can log on locally, run as service)
                  - Security Options (UAC level, LAN Manager auth level, SMB signing)
                Reveals misconfigurations that lead to privilege escalation.
  Output      : audit_secpol.cfg (INI format, auto-deleted after upload)
  Elevation   : Required
  Compatibility: Windows 10/11 Pro, Enterprise (limited on Home)

--------------------------------------------------------------------------------

[12] export_auditpol
  File        : export_auditpol.bat
  Description : Dumps all advanced audit policy settings via auditpol.
  Purpose     : Shows which security events are being audited (logged) on the
                system, across all categories:
                  - Account Logon / Logon-Logoff events
                  - Privilege Use
                  - Object Access
                  - Policy Change
                  - Process Tracking
                Useful for detecting gaps in logging that allow attackers to
                operate undetected.
  Output      : audit_auditpol.txt
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------
  SECTION 4 — HARDWARE ENUMERATION PAYLOADS
--------------------------------------------------------------------------------

[13] export_drivers
  File        : export_drivers.bat
  Description : Enumerates all installed PnP drivers via pnputil.
  Purpose     : Lists every signed and unsigned driver on the system with
                provider, version, and date. Used to identify:
                  - Outdated/vulnerable drivers (e.g., BYOVD attacks)
                  - Unsigned or third-party kernel drivers
                  - Rootkit indicators
  Output      : audit_drivers.txt
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------

[14] export_devices
  File        : export_devices.bat
  Description : Enumerates all PnP devices via pnputil.
  Purpose     : Lists every hardware device registered with Windows including
                USB devices, HID devices, network adapters, and virtual devices.
                Useful for detecting unauthorized hardware (USB keyloggers,
                rogue network adapters, etc).
  Output      : audit_devices.txt
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------
  SECTION 5 — POLICY ANALYSIS PAYLOADS (RSOP / GPO)
--------------------------------------------------------------------------------

[15] export_rsop_computer
  File        : export_rsop_computer.bat
  Description : Queries the RSOP computer namespace via WMI.
  Purpose     : Resultant Set of Policy (RSOP) shows the FINAL merged result of
                all Group Policy Objects applied to the computer. Uses legacy WMI
                (Get-WmiObject) to query root\rsop\computer namespace.
                Exports structured JSON with policy name, key, value, and setting.
                Good for: automation, audit scripting, domain policy analysis.
  Output      : audit_rsop_computer.json
  Elevation   : Required
  Compatibility: Windows 10/11 Pro, Enterprise (domain-joined preferred)

--------------------------------------------------------------------------------

[16] export_rsop_user
  File        : export_rsop_user.bat
  Description : Queries the RSOP user namespace via modern CIM.
  Purpose     : Same as RSOP computer but scoped to the current user's applied
                policies. Uses Get-CimInstance (faster, more modern than WMI)
                to query root\rsop\user namespace.
                Useful for: user-specific GPO analysis, per-user restrictions.
  Output      : audit_rsop_user.json
  Elevation   : No (current user scope)
  Compatibility: Windows 10/11 Pro, Enterprise (domain-joined preferred)

--------------------------------------------------------------------------------
  SECTION 6 — USER & ACCOUNT PAYLOADS
--------------------------------------------------------------------------------

[17] export_net_users
  File        : export_net_users.bat
  Description : Enumerates all local user accounts via net user.
  Purpose     : Lists every local user account and dumps per-user details:
                  - Account active/disabled state
                  - Password last set / expiry
                  - Logon hours and workstation restrictions
                  - Group memberships
                  - Account lockout state
                Useful for: identifying privileged accounts, disabled accounts
                used for persistence, and password policy enforcement.
  Output      : audit_net_users.txt
  Elevation   : Recommended
  Compatibility: All Windows versions

--------------------------------------------------------------------------------
  SECTION 7 — GROUP POLICY FORENSICS PAYLOADS
--------------------------------------------------------------------------------

[18] export_gp_cache
  File        : export_gp_cache.bat
  Description : Lists the Group Policy cache directory.
  Purpose     : The GP cache at C:\ProgramData\Microsoft\Group Policy\History\
                contains the applied GPO GUIDs, cached policy files, and
                timestamps of the last policy refresh. This payload enumerates
                all files and folders in this directory recursively and exports
                a JSON manifest. Useful for:
                  - Offline forensic analysis
                  - Identifying which GPOs were applied
                  - Detecting GPO tampering or missing policies
  Output      : audit_gp_cache.json
  Elevation   : Required (ProgramData access)
  Compatibility: Windows 10/11 Pro, Enterprise (limited on Home)

--------------------------------------------------------------------------------
  SECTION 8 — COMBINED PAYLOADS
--------------------------------------------------------------------------------

[19] full_audit
  File        : full_audit.bat
  Description : Runs ALL individual exports in a single injection.
  Purpose     : Performs a complete one-shot system audit by collecting all 9
                standard data points in sequence and uploading them all to the Pi:
                  1. System info (JSON)
                  2. HKLM Policies registry
                  3. HKCU Policies registry
                  4. Services registry
                  5. Control registry
                  6. Firewall rules
                  7. Defender preferences
                  8. Driver list
                  9. Device list
                Best used for a quick full sweep when time is limited.
  Output      : All 9 audit files
  Elevation   : Required
  Compatibility: Windows 10/11 Home, Pro, Enterprise

--------------------------------------------------------------------------------

[20] upload_files
  File        : upload_files.bat
  Description : Uploads pre-existing audit files to the Pi.
  Purpose     : If audit files are already present on disk (from a previous
                manual collection or a failed upload), this payload uploads
                them to the Pi without re-running the collection commands.
                Useful for retrying failed uploads.
  Output      : Uploads all existing audit_*.* files from C:\
  Elevation   : No
  Compatibility: All Windows versions

================================================================================
  COMPATIBILITY SUMMARY
================================================================================

  Payload                  | Home | Pro | Enterprise | Elevation
  -------------------------|------|-----|------------|----------
  test                     |  YES |  YES|  YES       |  No
  sysinfo                  |  YES |  YES|  YES       |  No
  compliance               |  YES |  YES|  YES       |  Recommended
  export_policies          |  YES |  YES|  YES       |  Required
  export_user_policies     |  YES |  YES|  YES       |  No
  export_registry_hkcu     |  YES |  YES|  YES       |  No
  export_services          |  YES |  YES|  YES       |  Required
  export_control           |  YES |  YES|  YES       |  Required
  export_firewall          |  YES |  YES|  YES       |  Required
  export_defender          |  YES |  YES|  YES       |  Required
  export_secedit           |  NO  |  YES|  YES       |  Required
  export_auditpol          |  YES |  YES|  YES       |  Required
  export_drivers           |  YES |  YES|  YES       |  Required
  export_devices           |  YES |  YES|  YES       |  Required
  export_rsop_computer     |  NO  |  YES|  YES       |  Required
  export_rsop_user         |  NO  |  YES|  YES       |  No
  export_net_users         |  YES |  YES|  YES       |  Recommended
  export_gp_cache          |  NO  |  YES|  YES       |  Required
  full_audit               |  YES |  YES|  YES       |  Required
  upload_files             |  YES |  YES|  YES       |  No

================================================================================
  SKIPPED METHODS (GUI / INTERACTIVE — NOT INJECTABLE)
================================================================================

  The following methods were considered but cannot be automated via HID injection
  because they require interactive GUI or external binary downloads:

  - Event Viewer (GroupPolicy Operational Log) — GUI only
  - Process Monitor (ProcMon) — requires download + GUI interaction
  - Sysinternals AccessChk — requires binary download to target
  - rsop.msc — MMC snap-in, GUI only
  - NTUSER.DAT hive loading — requires knowing username and unmounted hive

================================================================================
