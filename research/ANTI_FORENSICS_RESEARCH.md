# Anti-Forensic Techniques — Global Threat Intelligence Research
## For PITBULL Integration — July 2025

### Sources: DEF CON 32/33, Troopers 2025, hack.lu 2025, DefCamp 2023-2025, RomHack 2024, OffensiveCon 2025, Phrack #72, ASEC, Mandiant, Trend Micro, Cisco Talos, Google Threat Intelligence, Sandfly Security, Cyber Shafarat

---

## 1. ANTI-FORENSIC FRAMEWORK (Dr. Marcus Rogers Classification)

Five categories:
1. **Data Hiding** — conceal data to render detection difficult
2. **Artifact Wiping** — permanently delete files/traces
3. **Trail Obfuscation** — confuse forensic process (log manipulation, timestomping)
4. **Attacks Against Forensics Tools** — disable/malfunction forensic software
5. **Physical** — physical destruction of media

---

## 2. NORTH KOREA (Lazarus Group / Kimsuky / APT37)

### Lazarus Group Anti-Forensics (ASEC Analysis)

#### Data Hiding
- **3-stage encryption**: Loader decrypts encrypted PE → PE runs in memory → decrypts config for C2
- **System folder camouflage**: Malware hidden in `C:\ProgramData\`, `C:\ProgramData\Microsoft\`, `C:\Windows\System32\`
- **Fake system folders**: Create `MicrosoftPackages` inside `ProgramData` to mimic legit folders
- **File impersonation**: Malware disguised as system files (e.g. `DapowSyncProvider.dll` mimicking `notepad.exe` timestamps)

#### Artifact Wiping
- **Overwrite-then-delete**: Malware data overwritten before deletion (prevents file recovery/carving)
- **Filename randomization**: Rename before delete
- **Batch prefetch deletion**: Delete all prefetch files to erase execution traces
- **USN Journal manipulation**: Delete USN journal entries to hide file operation history

#### Trail Obfuscation
- **Timestomping**: Copy timestamps from legitimate system files (e.g. notepad.exe) to malware
- **$STANDARD_INFORMATION forgery**: Modify NTFS $STANDARD_INFORMATION timestamps to match legit files
- **$FILE_NAME vs $STANDARD_INFORMATION mismatch**: $FILE_NAME timestamps are harder to fake — forensic analysts compare both

### Lazarus RemotePE (2025-2026) — Memory-Only RAT
- **Zero disk footprint**: Entire RAT lives in process memory, no files dropped
- **DPAPI for credential storage**: Uses Windows Data Protection API — keys never touch disk
- **Reflective PE loading**: Loads PE files directly into memory without touching disk
- **No prefetch artifacts**: Nothing executed from disk = no prefetch entries
- **No file timestamps**: No files = no timestamp forensics
- **Process injection**: Hides within legitimate processes

### Kimsuky Linux Rootkit (Phrack #72 Leak, Aug 2025)
- **LKM (Loadable Kernel Module) rootkit** based on khook library
- **Hidden kernel module**: Module hidden from `lsmod` listing
- **Hidden processes**: Backdoor processes invisible to `ps`/`top`
- **Hidden network activity**: Backdoor connections invisible to `netstat`/`ss`
- **Hidden persistence files**: Files under `/etc/init.d/` and `/etc/rc*.d/` hidden from `ls`
- **Magic packet activation**: Backdoor wakes on magic packet on ANY port — no fixed port to scan
- **Anti-forensic shell spawning**: Shells spawned by backdoor have anti-forensic properties
- **Encrypted C2 traffic**: All backdoor traffic encrypted
- **Module location**: `/usr/lib64/tracker-fs` (hidden), backdoor at `/usr/include/tracker-fs/tracker-efs`
- **Persistence**: `/etc/init.d/tracker-fs`, `/etc/rc2.d/S55tracker-fs`, `/etc/rc3.d/S55tracker-fs`, `/etc/rc5.d/S55tracker-fs`

### APT37 (Reconnaissance General Bureau)
- **Rust backdoor**: Memory-efficient, hard to reverse-engineer (no symbol tables)
- **Python loader**: Fileless execution via Python in-memory loading
- **EtherHiding**: Malware payloads hidden in Ethereum blockchain smart contracts (Mandiant 2025)

---

## 3. RUSSIA (APT28/Fancy Bear / Turla)

### Turla Backdoor (2024 Analysis) — ETW/EventLog/AMSI Bypass

#### ETW Evasion
- **PSEtwLogProvider disabling**: Sets `m_enabled` field to 0 via reflection
  ```powershell
  [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
  ```
- **EventWrite patching**: Patches entry point with `\x48\x31\xc0\xc3` (xor rax,rax; ret) → always returns 0 (success)
- **EtwEventWrite patching**: Patches with `\x48\x33\xc0\xc3` (xor rax,rax; ret) → always returns 0

#### EventLog Evasion
- **ReportEventW patching**: Patches EventLog function to prevent events from being written
- **In-process PowerShell**: Creates PowerShell Runspace inside malware process — all functions patched in-process

#### AMSI Bypass
- **AmsiOpenSession patching**: Patches to always return success without scanning
- **AmsiScanBuffer patching**: Same approach — prevents buffer content scanning

### APT28/Fancy Bear (GRU Unit 26165)
- **Living off the Land (LOLBin) abuse**: Uses native Windows tools (wevtutil, PowerShell, ntdsutil) for log manipulation
- **Event ID 1102 clearing**: Clear security log after credential dump operations
- **Credential dump timing**: Execute 4662/4663 (object access) → clear 1102 → no audit trail
- **WinRM session abuse**: Compromise intermediate log-forwarding to modify forwarded logs

### Turla TinyTurla (2024)
- **Fileless backdoor**: PowerShell-based, no binaries on disk
- **Shortcut file persistence**: LNK files with embedded payloads
- **Registry-only persistence**: No file system artifacts

---

## 4. CHINA (APT41 / APT10 / APT3 / APT27)

### APT41 (DUST Campaign, 2023-2024)
- **MoonWalk**: Memory-resident backdoor with reflective loading
- **DodgeBox**: Modular loader that never touches disk — entirely in-memory execution
- **ShadowPad**: Fileless malware with reflective DLL injection, runs entirely in memory
- **Real-time event suppression**: Hooks `eventlog.dll` and ETW APIs to prevent events from being logged (not just deleting after — real-time silencing at kernel level)

### Chinese Event Log Manipulation (Cyber Shafarat, April 2025)

#### Log Clearing
- **wevtutil cl Security**: Native Windows tool to clear security logs
- **Targeted Event ID deletion**: Remove specific event IDs (4624, 4625, 4724, 4728, 4732) rather than clearing all
- **PowerShell Clear-EventLog**: Programmatic log clearing

#### Log Spoofing (Advanced)
- **Inject fake 4624 (logon) events**: Simulate routine access during lateral movement
- **Suppress 4625 (failed logon) events**: Remove failed authentication traces
- **Suppress 4724 (password reset)**: Hide credential manipulation
- **Suppress 4728/4732 (privilege escalation)**: Hide group membership changes
- **Spoof 4662 (directory access)**: Modify source hostname/timestamp to mimic legitimate replication

#### Advanced Techniques
1. **Time Shifting + NTFS Timestamp Forgery**: Combine event log manipulation with Timestomp/SetMACE — forged events align with modified file timestamps for coherent deception
2. **EDR/AV API Hooking**: Inject into security agent processes, hook `eventlog.dll` functions, suppress events before logging
3. **ETW manipulation**: Use undocumented APIs to prevent events (4624, 4672, 7040) from reaching SIEMs
4. **Decoy Events**: Generate noisy low-severity events (failed logons, PowerShell errors) to consume analyst time and SIEM telemetry limits
5. **SIEM Correlation Breaking**: Insert buffer events between attack stages to break temporal correlation rules (e.g., 4624→4672 within 5 seconds)
6. **Log Forwarding Interception**: Compromise WinRM/Event Collector service to modify forwarded logs while local logs remain clean
7. **Sysmon Log Injection**: Deploy fake Sysmon events via modified XML config or tools like `sysmonlogfaker`
8. **DCSync obfuscation**: Modify source host metadata to mimic expected enterprise replication patterns

### APT10 (menuPass / Cloud Hopper)
- **Supply chain intrusion**: Compromise MSPs to access target networks
- **Log narrative engineering**: Not just hiding tracks — building a deceptive story for defenders

---

## 5. ROMANIA (DefCamp / RomHack)

### DefCamp 2023-2025 (Bucharest)
- Major CEE cybersecurity conference — anti-forensics covered in malware behavior tracks
- **Andrei Bozeanu (CERT-RO)**: 25+ years malware research, attack detection techniques
- **Ioan Iacob (CrowdStrike)**: Malware and digital forensics — unique behavior patterns in attack scenarios
- Focus on: cloud vulnerabilities, AI impact on security, quantum computing threats

### RomHack 2024 (Rome, Italian-Romanian connection)
- **MalOpSec 2: EDR The Great Escape** (Silvio La Porta & Antonio Villani)
  - Red team techniques for EDR bypass
  - Memory-only execution techniques
  - Behavioral detection evasion
  - Also presented at OffensiveCon 2025 (Berlin)

### Troopers 2025 / hack.lu 2025
- **"Anti-Forensics — You are doing it wrong"** (Stephan Berger, InfoGuard CSIRT)
  - USN Journal deletion techniques
  - Shellbag clearing
  - Timestamp manipulation
  - Common anti-forensics mistakes that IR consultants see
  - Focus on what actually works vs what attackers think works

---

## 6. INDIA

### Future Crime Summit 2025 (Delhi)
- Biggest Global Hackathon on Digital Forensics
- Focus on digital forensics challenges and solutions

### C3iHub / IFIP WG 11.9 International Conference on Digital Forensics
- Indian academic forensics research
- Collaboration with University of Tulsa
- Focus on defensive forensics and detection

### Indian APT Techniques
- **SideWinder**: Uses LOLBins, PowerShell fileless execution, macro-based initial access
- **Patchwork**: Uses in-memory execution, reflective loading, minimal disk footprint
- **DoNot Team**: Uses .NET reflection, in-memory payload execution, scheduled task persistence with log clearing

---

## 7. DEF CON 32/33 (2024-2025)

### DEF CON 33 (2025)
- **"Countering Forensics Software by Baiting Them"**: Honey tokens as trip wires, encryption against forensic tools
- **AIMaL (Artificially Intelligent Malware Launcher)**: Modular red team framework for AV/EDR/IDS evasion simulation
- **BOAZ**: Multilayered AV/EDR evasion framework (Assembly, C, C++)

### DEF CON 32 (2024)
- **"Defeating EDR Evading Malware with Memory Forensics"**: EDR evasion vs memory forensics detection
- Focus on memory-resident malware and detection challenges

---

## 8. PRACTICAL ANTI-FORENSIC TECHNIQUES FOR PITBULL

### Linux (PITBULL's native platform)

#### Log Wiping
- **/var/log manipulation**: Clear auth logs, syslog, kern.log, audit logs
- **journalctl --vacuum-time=1s**: Clear systemd journal entries
- **auditctl -D**: Delete all audit rules
- **>/var/log/wtmp**: Clear login history
- **>/var/log/btmp**: Clear failed login attempts
- **>/var/log/lastlog**: Clear last login records

#### Timestamp Manipulation
- **touch -r reference_file target_file**: Copy timestamps from reference file
- **touch -t YYYYMMDDHHMM**: Set specific timestamp
- **stat -x file**: Check current timestamps (Mac/BSD)
- **debugfs + set_inode_field**: Ext4 inode timestamp manipulation

#### Process Hiding
- **PID namespace**: Run processes in isolated PID namespace
- **/proc/PID hiding**: Mount over /proc/PID to hide process
- **LD_PRELOAD**: Hook libc functions (readdir, readlink) to hide files/processes
- **Kernel module**: Hook syscalls (getdents, read) at kernel level

#### Memory-Only Execution
- **memfd_create()**: Create anonymous file in memory, execute from it
- **/proc/self/exe**: Self-execution from memory
- **Reflective ELF loading**: Load shared libraries from memory
- **ptrace injection**: Inject shellcode into running process memory

#### Network Trace Removal
- **conntrack -F**: Flush connection tracking table
- **iptables -Z**: Zero packet/byte counters
- **ss/netstat**: Connections are ephemeral — close and they're gone
- **Tor circuit rotation**: NEWNYM to change circuit

#### File System Anti-Forensics
- **shred -vfzu -n 3**: Overwrite file 3 times + zeros + remove
- **wipe**: Secure file deletion
- **dd if=/dev/urandom of=file**: Overwrite with random data
- **debugfs + unlink**: Direct inode unlinking (bypasses normal deletion)

### Network-Level
- **Tor**: Route all traffic through Tor, rotate circuits
- **Proxy chains**: Chain multiple proxies through different jurisdictions
- **MAC spoofing**: `ip link set dev eth0 address XX:XX:XX:XX:XX:XX`
- **DNS over Tor**: Prevent DNS leaks
- **SNI spoofing**: Domain fronting via CDN

### Neo4j Trace Wiping (PITBULL-specific)
- **Memory node deletion**: `MATCH (m:Memory) WHERE m.memory_type='episodic' DELETE m`
- **Log clearing**: Clear PITBULL application logs
- **Mission history purge**: Remove mission records from `_missions` dict

---

## 9. PROPOSED PITBULL ANTI-FORENSIC MODULE

### Architecture
```
app/core/antiforensics.py
├── LogWiper
│   ├── wipe_system_logs()
│   ├── wipe_journalctl()
│   ├── wipe_audit_logs()
│   └── wipe_auth_logs()
├── TimestampManipulator
│   ├── timestomp_file(file, reference_file)
│   ├── randomize_timestamps(files)
│   └── restore_timestamps(snapshot)
├── ProcessHider
│   ├── hide_process(pid)
│   ├── unhide_process(pid)
│   └── list_hidden_processes()
├── MemoryExecutor
│   ├── memfd_execute(binary)
│   ├── reflective_load(elf_bytes)
│   └── ptrace_inject(pid, shellcode)
├── NetworkCleaner
│   ├── flush_conntrack()
│   ├── zero_iptables_counters()
│   ├── rotate_tor_circuit()
│   └── spoof_mac(interface)
├── FileWiper
│   ├── secure_delete(path, passes=3)
│   ├── wipe_directory(path)
│   └── wipe_free_space(device)
├── Neo4jCleaner
│   ├── purge_episodic_memory(target)
│   ├── purge_mission_history()
│   ├── purge_exploit_attempts(target)
│   └── sanitize_logs()
└── OpSecManager
    ├── full_sanitize(target)
    ├── quick_wipe()
    └── ghost_mode(enable/disable)
```

### Integration Points
- **Post-mission cleanup**: After exploration mission completes, optionally sanitize
- **Exploit post-execution**: After exploit attempt, wipe traces
- **Manual trigger**: Dashboard button for "Ghost Mode" — full system sanitize
- **Auto-clean**: Cron job that periodically purges old episodic memories

### ATT&CK Mapping
- T1070 — Indicator Removal
- T1070.001 — Clear Windows Event Logs (not applicable for Linux)
- T1070.002 — Clear Linux or Mac System Logs
- T1070.003 — Clear Command History
- T1070.004 — File Deletion
- T1070.006 — Timestomp
- T1027 — Obfuscated Files or Information
- T1140 — Deobfuscate/Decode Files or Information
- T1620 — Reflective Code Loading
- T1059.004 — Unix Shell
- T1562 — Impair Defenses
- T1562.001 — Disable or Modify Tools
- T1562.006 — Clear Windows Event Logs
- T1070.002 — Clear Linux or Mac System Logs