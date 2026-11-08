# DFCS Day 1 Assignment — Foundations, Linux & Networks

## Task A: Malware Matrix & SME Threat Assessment

### Malware Matrix

| Type | Definition in your own words | Named example + year | How it spread | Primary impact |
| :--- | :--- | :--- | :--- | :--- |
| **Virus** | Malicious code attached to a legitimate host program or file that requires human execution to replicate and spread. | **CIH (Chernobyl)** (1998) | Embedded in executable files (`.exe`) via internet downloads and software pirate CDs. | Overwrote critical system data and corrupts system BIOS on execution. |
| **Worm** | Self-replicating malware that spreads autonomously across networks by exploiting system vulnerabilities without user interaction. | **WannaCry** (2017) | Exploited the SMBv1 vulnerability (EternalBlue/CVE-2017-0144) across open port 445. | Encrypted host systems network-wide, causing massive operational paralysis and requesting Bitcoin payouts. |
| **Trojan** | Malicious software disguised as a benign or useful application to trick users into running it. | **Emotet** (2014) | Phishing emails containing malicious Word/Excel macro attachments or links. | Opened backdoors, stole banking credentials, and dropped secondary payloads. |
| **Ransomware** | Malware designed to encrypt a target system's files or steal confidential data to demand payment for access or non-leakage. | **LockBit** (2019) | Exploited unpatched VPNs, exposed RDP ports, and compromised credentials. | Encrypted enterprise servers and leaked stolen corporate data on public leak sites (Double Extortion). |
| **Spyware** | Stealthy software designed to monitor user activities, track browsing history, and harvest sensitive information silently. | **Pegasus** (2016) | Zero-click exploits via messaging apps (iMessage/WhatsApp) and malicious links. | Monitored microphone, camera, location data, and extracted encrypted chat logs. |
| **Adware** | Unsolicited software that forcefully displays advertisements and redirects browser traffic to generate ad revenue. | **Fireball** (2017) | Bundled stealthily inside free software downloads and browser extensions. | Highjacked default search engines, injected invasive ads, and executed arbitrary remote code. |
| **Rootkit** | Privilege-escalation software operating at system level/kernel to grant continuous root access while concealing its presence. | **Stuxnet** (2010) | Physical USB flash drives, exploiting zero-day vulnerabilities in Windows and Siemens PLCs. | Manipulated industrial centrifuge speeds while faking normal telemetry readings to operators. |
| **Keylogger** | Hardware or software module configured to silently record every keypress on a keyboard to capture credentials. | **Hawkeye** (2013) | Delivered via spear-phishing emails containing malicious keylogger executables. | Intercepted system login credentials, web passwords, and corporate emails. |
| **Botnet Agent** | Malware that infects a target machine to enlist it as a node ("zombie") in a remotely controlled network. | **Mirai** (2016) | Scanned public IP address space for IoT devices with default factory credentials. | Enlisted millions of devices to launch overwhelming volumetric DDoS attacks. |
| **Fileless / Living-off-the-Land** | In-memory malware that executes malicious commands using legitimate system binaries (e.g., PowerShell, WMI) without dropping files to disk. | **Astaroth** (2019) | Malicious spam links launching native Windows management tools (WMIC, Bitsadmin). | Harvested and exfiltrated user credentials directly from RAM without triggering traditional AV file scans. |
| **Logic Bomb** | A piece of code intentionally inserted into software that lies dormant until specific execution conditions or time triggers are met. | **Siemens Logic Bomb** (2016) | Directly inserted into custom spreadsheet automation scripts by an insider employee. | Froze spreadsheet operations after set intervals, forcing the business to pay for recurring repair contracts. |
| **Bootkit** | An advanced rootkit variant that infects the Master Boot Record (MBR) or VBR to execute before the operating system kernel loads. | **Rovnix** (2011) | Malicious drive-by downloads and compromised software installers. | Loaded persistence mechanisms below OS-level detection prior to Windows kernel startup. |

### Threat Analysis for Pakistani SMEs

For a Pakistani Small and Medium Enterprise (SME), **Ransomware** poses the most catastrophic operational threat. Pakistani SMEs often operate with flat network architectures, unpatched operating systems, and unverified off-site backups, leaving them vulnerable to rapid network-wide file encryption. A single successful breach halts revenue-generating activities instantly, and limited operating cash flow means most SMEs cannot afford double-extortion demands or business interruption costs.

---

## Task B: Practical Lab Write-ups

### Option B2: File Permissions with `chmod`

1. **Initial File Creation & Baseline:**
   - Command: `echo "Sensitive Security Data" > practice.txt && ls -l practice.txt`
   - Output: `-rw-r--r-- 1 kali kali 24 Oct 24 10:00 practice.txt`
   - *Explanation:* Default permission `644` (`rw-r--r--`) allows owner read/write access, while group and others retain read-only permission.

2. **First Change (Symbolic `chmod o-r`):**
   - Command: `chmod o-r practice.txt && ls -l practice.txt`
   - Output: `-rw-r----- 1 kali kali 24 Oct 24 10:01 practice.txt`
   - *Explanation:* `o-r` specifically strips read access (`r`) from external users (`others`).

3. **Second Change (Octal `chmod 640`):**
   - Command: `chmod 640 practice.txt && ls -l practice.txt`
   - Output: `-rw-r----- 1 kali kali 24 Oct 24 10:02 practice.txt`
   - *Explanation:* Octal `640` explicitly assigns `6` (`rw-`) to Owner, `4` (`r--`) to Group, and `0` (`---`) to Others.

4. **Third Change (Octal `chmod 600`):**
   - Command: `chmod 600 practice.txt && ls -l practice.txt`
   - Output: `-rw------- 1 kali kali 24 Oct 24 10:03 practice.txt`
   - *Explanation:* Octal `600` removes all read/write/execute rights from Group and Others, leaving access restricted solely to the owner.

---

### Option B4: OpenSSL Encryption & Header Analysis

1. **Encryption Command:**
   - Command: `openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc`

2. **Header Inspection (`xxd`):**
   - Command: `xxd -l 16 secret.enc`
   - Output:
     ```text
     00000000: 5361 6c74 6564 5f5f a7a0 ff99 589c 686d  Salted__....X.hm
     ```

3. **Technical Explanation of `Salted__` Header:**
   The ASCII identifier `Salted__` (Hex: `53 61 6c 74 65 64 5f 5f`) is an 8-byte magic header prepended by OpenSSL whenever the `-salt` flag is used. This header tells OpenSSL during decryption that the subsequent 8 bytes represent the random salt used during key derivation, preventing rainbow-table attacks.
