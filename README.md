# Interpreting-Scan-Results-and-CVSS-Scoring

**Author:** Dashane James  
**Lab Environment:** VMware Workstation | Kali Linux | Metasploitable 2 | OpenVAS/GVM  
**Purpose:** Read vulnerability scan results like an analyst: break down CVSS vectors, identify potential false positives, and build a prioritized remediation order based on context rather than score alone.  
**Status:** 🔵 Completed

---

## 📋 Overview

A vulnerability scanner hands you a list. The analyst's job is to turn that list into a decision: what gets fixed first, what needs more investigation, and what might not be a real finding at all.

This repository works through the Day 08 OpenVAS/GVM scan results in depth. The three highest-CVSS findings are broken down vector by vector to explain exactly what each score component means in practical terms. One finding is examined as a potential false positive. Then all Critical and High findings are ranked in the order a real organization should address them — not by CVSS score alone, but by actual exploitability, what an attacker could do with each vulnerability, and what realistic compensating controls exist.

The core takeaway from this exercise: CVSS scores are a starting point for triage, not a final answer. A 9.8 in an isolated lab environment is not the same risk as a 9.8 on a public-facing production server. An analyst who can explain the difference — and can identify when a score either overstates or understates real impact — is doing more than running a scanner.

---

## 🧪 Lab Environment

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation (Host-Only Network) |
| Attacker Machine | Kali Linux 2026.1, `192.168.79.129` |
| Target Machine | Metasploitable 2, `192.168.79.130` |
| Scan Data Source | OpenVAS/GVM Full and Fast scan (Day 08) |
| Reference Source | NVD (nvd.nist.gov) |
| Network Type | Host-Only (isolated, no internet exposure) |
| Host OS | Windows 11, ASUS Vivobook 14 |

> ⚠️ **Note:** All activity was performed in a controlled, isolated lab environment against a deliberately vulnerable machine. No unauthorized access to live networks was performed.

---

## 🛠️ Tools Used

- **OpenVAS/GVM (scan data)**: The Day 08 Full and Fast scan results, exported as PDF for structured reference
- **NVD (National Vulnerability Database)**: Used to verify CVSS vector strings and understand the technical scope of each finding
- **nvd.nist.gov CVSS calculator**: Used to confirm score components match the published vectors

---

## 🔬 Tasks / Assessments Performed

### 1. Export the OpenVAS scan as PDF

The completed scan report was exported from the GSA web UI for reference:

1. Navigate to **Scans → Reports**
2. Open the completed scan report
3. Select **PDF** from the export format dropdown
4. Download and save the report

The exported PDF serves as the source document for the analysis below: a fixed-point snapshot of what the scanner found, how it scored each finding, and what NVT was responsible for the detection.

---

### 2. Top 3 CVSS findings: full vector breakdown

The three highest-scoring findings from the scan, each looked up on nvd.nist.gov and broken down component by component.

---

#### Finding 1: CVE-2011-2523 — vsftpd 2.3.4 Backdoor (Port 21)

**CVSS v3.1 Score: 9.8 Critical**  
**Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Component | Value | Meaning |
|---|---|---|
| Attack Vector (AV) | Network (N) | Exploitable remotely, no physical or adjacent-network access required |
| Attack Complexity (AC) | Low (L) | No special conditions, no race conditions, repeatable every time |
| Privileges Required (PR) | None (N) | Any unauthenticated connection can trigger the backdoor |
| User Interaction (UI) | None (N) | The attacker acts alone; no victim needs to click anything |
| Scope (S) | Unchanged (U) | Exploitation is contained to the vsftpd process context |
| Confidentiality (C) | High (H) | Complete access to data the process can reach |
| Integrity (I) | High (H) | Complete ability to modify data |
| Availability (A) | High (H) | Can crash or disable the service |

**What this means in practice:** A remote attacker sends a connection to port 21 with a username containing a smiley face (`:)`) and receives back an open shell on port 6200, running as root. No credentials. No exploitation tool required beyond a basic TCP connection. This vulnerability was previously confirmed through live exploitation in the NSE lab: `uid=0(root) gid=0(root)`.

The 9.8 is accurate and appropriate. The only reason it isn't 10.0 is the Scope component being "Unchanged" (meaning the attack doesn't automatically cross a security boundary into another system). In practice, a root shell on the target is already worst-case.

---

#### Finding 2: CVE-2010-2075 — UnrealIRCd 3.2.8.1 Backdoor (Port 6667)

**CVSS v3.1 Score: 9.8 Critical**  
**Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Component | Value | Meaning |
|---|---|---|
| Attack Vector (AV) | Network (N) | Remotely exploitable over IRC protocol on port 6667 |
| Attack Complexity (AC) | Low (L) | Single crafted message triggers the backdoor reliably |
| Privileges Required (PR) | None (N) | No IRC registration or authentication required |
| User Interaction (UI) | None (N) | Attacker-only action, no user participation |
| Scope (S) | Unchanged (U) | Contained to the UnrealIRCd process |
| Confidentiality (C) | High (H) | Full read access to data the process can reach |
| Integrity (I) | High (H) | Full write access |
| Availability (A) | High (H) | Service can be disabled |

**What this means in practice:** An attacker sends a specially crafted message to the IRC port and receives a remote command shell. Like the vsftpd backdoor, this was planted in the distributed source archive rather than the code repository, meaning anyone who downloaded UnrealIRCd 3.2.8.1 during a specific window received a compromised binary without knowing it.

The vector is identical to CVE-2011-2523. Both are the same category of finding: supply chain compromise, intentional backdoor, no authentication, network-accessible. The primary difference for prioritization is that this service was not discovered by the Nmap fast scan. It requires a full-port scan or a vulnerability scanner with its own port discovery to surface.

---

#### Finding 3: CVE-2004-2687 — distccd Arbitrary Command Execution (Port 3632)

**CVSS v2 Score: 9.3 High** (no official CVSS v3 score; older CVE predates v3 scoring)  
**Vector (v2):** `AV:N/AC:L/Au:N/C:C/I:C/A:C`

| Component | Value | Meaning |
|---|---|---|
| Access Vector (AV) | Network (N) | Remotely exploitable over the distccd protocol |
| Access Complexity (AC) | Low (L) | No special conditions required |
| Authentication (Au) | None (N) | No credentials, no authentication mechanism at all |
| Confidentiality (C) | Complete (C) | Full read access to anything the daemon can reach |
| Integrity (I) | Complete (C) | Full write access |
| Availability (A) | Complete (C) | Daemon can be disabled |

**What this means in practice:** distccd is a distributed compiler daemon designed to allow build systems to offload compilation jobs to remote machines. On Metasploitable 2 it runs with no access controls, meaning any host on the network can send it a "compilation job" that is actually arbitrary shell commands. The commands execute as the `daemon` user, not root, which is a slight mitigation compared to the backdoor findings above. The daemon user still has read access to most of the filesystem and the ability to pivot further in a real environment.

The absence of a CVSS v3 score for this CVE is worth noting: older vulnerabilities often lack v3 scoring because no one has gone back to recalculate them. When only a v2 score exists, you interpret it with that framework's components (Authentication instead of Privileges Required, Access Complexity instead of Attack Complexity) but the practical severity analysis is the same.

---

### 3. Identifying a potential false positive

**Finding in question:** Multiple OpenVAS findings flagging **OpenSSH 4.7p1** for a range of CVEs affecting versions prior to specific upstream release numbers.

**Why this is worth flagging as a potential false positive:**

OpenVAS (and most vulnerability scanners) detect software versions from banners or probe responses and then flag all known CVEs for that version range. The version string returned by Metasploitable 2's SSH service is `OpenSSH 4.7p1 Debian 8ubuntu1`. The key detail is "Debian 8ubuntu1": this isn't a vanilla upstream OpenSSH 4.7p1 binary; it's a package maintained by the Ubuntu security team.

Ubuntu (and Debian) regularly backport security fixes into older package versions without incrementing the primary version number. A CVE fixed in upstream OpenSSH 5.1 might also be fixed in Ubuntu's 4.7p1 package through a targeted patch, while the version banner continues to read `4.7p1`. A scanner that only reads the version string will flag that CVE regardless.

**How to verify:** Pull the exact package version with `dpkg -l openssh-server` on the target. Cross-reference the Ubuntu Security Notice (USN) archive for openssh to see which CVEs were patched in the specific ubuntu package revision present on the system. If the Ubuntu patch list covers the CVEs the scanner flagged, those findings are false positives.

**Practical note:** This doesn't mean SSH findings should be dismissed. OpenSSH 4.7p1 is genuinely outdated and there will be real vulnerabilities present. The point is that a responsible analyst verifies scanner output rather than treating a version-based flag as a confirmed finding. In a credentialed scan, the scanner would have access to the actual installed package database and could make this determination automatically.

---

### 4. Critical and High findings ranked by patching priority

The following ranking uses CVSS scores as a baseline but adjusts order based on actual exploitability, what an attacker can do with each finding, and the realistic cost of the compensating controls available in this environment.

| Priority | Port/Service | Finding | CVSS | Reasoning |
|---|---|---|---|---|
| 1 | 21/tcp FTP | vsftpd 2.3.4 backdoor (CVE-2011-2523) | 9.8 | Intentional backdoor, confirmed root shell via NSE in Week 1, exploitable with a single TCP connection. Uninstall immediately. |
| 2 | 6667/tcp IRC | UnrealIRCd backdoor (CVE-2010-2075) | 9.8 | Same vulnerability class as vsftpd: intentional backdoor, no auth, remote shell. Would tie with #1 but vsftpd is patched first because it was confirmed live. |
| 3 | 5900/tcp VNC | No authentication configured | N/A | Any host on the network gets direct remote desktop access with zero interaction. No CVE required: this is a configuration failure. High urgency because exploitation requires no technical knowledge. |
| 4 | 445/tcp SMB | Samba username map script RCE (CVE-2007-2447) | 6.0 (v2) | CVSS v2 score of 6.0 understates this severely: it's unauthenticated RCE over SMB. Ranked #4 rather than #1-2 only because vsftpd and UnrealIRCd are literal backdoors. |
| 5 | 3632/tcp distccd | distccd arbitrary command execution (CVE-2004-2687) | 9.3 | Remote code execution with no auth, but executes as daemon user rather than root. Slightly lower urgency than the root-level findings above. |
| 6 | 23/tcp Telnet | Plaintext protocol, credentials in clear text | N/A | Critical risk to credential confidentiality. No direct RCE path without valid credentials, but credential capture was confirmed via TCPDump lab. Disable and replace with SSH. |
| 7 | 80/tcp HTTP | Apache 2.2.8 EOL, mod_proxy bypass (CVE-2011-3368) | ~7.5 | Exploitable but requires specific reverse proxy configurations; less immediately dangerous than services offering direct shells. |
| 8 | 445/tcp SMB | SMB signing disabled | ~6.8 (config) | Enables relay attacks but requires an attacker to already be in a man-in-the-middle position on the network. Lower urgency than direct exploitation paths. |
| 9 | 3306/tcp MySQL | MySQL 5.0.51a EOL, network-exposed | ~5.0 | Significant risk from being network-exposed on a database port with no firewall restriction. No direct RCE CVE confirmed for this version, but the exposure itself is the problem. |
| 10 | 22/tcp SSH | OpenSSH 4.7p1 CBC cipher weakness (CVE-2008-5161) | 5.9 | Low practical exploitability: requires a rare timing attack under specific conditions. Upgrade is still warranted but this is the lowest priority among findings that have a direct CVE. |

**Key principle behind this ranking:** Services with intentional backdoors or zero-credential remote access (1-3) take priority over vulnerabilities that require specific conditions (7-8). Configuration failures like missing VNC authentication rank alongside software CVEs because they're equally exploitable and often faster to fix.

---

## 📋 Executive Summary

A non-credentialed Full and Fast vulnerability scan of Metasploitable 2 (192.168.79.130) produced 162 findings across five severity levels, including 11 Critical and 24 High. The most severe findings center on three services that provide complete remote access with no authentication required: vsftpd 2.3.4 (CVE-2011-2523, port 21), UnrealIRCd 3.2.8.1 (CVE-2010-2075, port 6667), and VNC (port 5900) with no authentication configured. All three are exploitable by any host on the network with no credentials, no specialized tooling, and no user interaction. Samba 3.0.20 (CVE-2007-2447, port 445) presents unauthenticated remote code execution via SMB whose CVSS v2 score of 6.0 substantially understates real-world impact, a reminder that score-based triage requires analyst judgment to be meaningful. Two of the critical findings (distccd on port 3632 and UnrealIRCd on port 6667) were not returned by the Nmap fast scan in Week 1, confirming that automated vulnerability scanning surfaces exposure that manual port enumeration can miss. In this isolated lab environment, all findings are at full exposure with no compensating network controls; a production environment would include host firewalls, network segmentation, and IDS/IPS coverage that would reduce effective risk for some of these findings while leaving the underlying vulnerabilities unremediated.

---

## 🗺️ MITRE ATT&CK Mapping

| Action Performed | ATT&CK Tactic | Technique ID | Technique Name |
|---|---|---|---|
| NVD research on top 3 CVEs (vector breakdown and score verification) | Reconnaissance | T1588.006 | Obtain Capabilities: Vulnerabilities |
| Context-based prioritization of exploitable findings | Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning |

**Note on ATT&CK mapping for this lab:** The primary activities here are analyst-side: interpreting scan output, verifying CVE details, and building a remediation priority. MITRE ATT&CK is designed around adversary behaviors, so most of what's documented in this lab maps to the reconnaissance techniques an attacker would also use when reviewing scan output to decide what to exploit next. The analysis skills demonstrated here are the defensive mirror of those techniques.

---

## 🛡️ Defensive Recommendations

Based on findings and prioritization analysis:

1. **Treat intentional backdoors as a different category from CVEs:** vsftpd 2.3.4 and UnrealIRCd 3.2.8.1 are not software with vulnerabilities — they are malware distributed as software. No patch exists because the backdoor is the intended behavior of that specific version. Uninstall immediately; no further investigation needed.
2. **Require authentication for all remote access services:** VNC with no authentication is a configuration failure that takes minutes to exploit and minutes to fix. In any real environment this would be remediated before software CVEs are prioritized.
3. **Don't trust CVSS scores without reading the description:** CVE-2007-2447 (Samba, CVSS v2 6.0) is unauthenticated remote code execution. The score doesn't reflect that. Analysts who rely solely on numeric scores will systematically under-prioritize this class of finding.
4. **Use credentialed scans in production:** A non-credentialed scan can't distinguish between a patched Ubuntu package and the vulnerable upstream version it's based on. Adding scan credentials produces fewer false positives and gives more accurate remediation guidance.
5. **Establish a remediation SLA by severity:** In a production environment, a defined SLA (e.g., Critical: 24 hours, High: 7 days, Medium: 30 days) converts a findings list into accountable action items rather than a document that sits unaddressed.

---

## 🔑 Technical Notes

```bash
# Export scan report as PDF from GSA
# Scans → Reports → [select completed report] → Report Format: PDF → Download

# CVSS v3.1 score ranges (for reference):
# Critical:  9.0 - 10.0
# High:      7.0 - 8.9
# Medium:    4.0 - 6.9
# Low:       0.1 - 3.9
# None/Info: 0.0

# CVSS v3.1 Attack Vector values:
# N (Network):          Exploitable remotely across the internet or a routed network
# A (Adjacent):         Exploitable only from the same network segment (LAN, VLAN, Bluetooth)
# L (Local):            Exploitable only with local OS access (logged-in user)
# P (Physical):         Requires physical device access

# CVSS v3.1 Attack Complexity values:
# L (Low):    No special conditions; attack is repeatable every time
# H (High):   Requires specific conditions to be met (race condition, specific config)

# CVSS v3.1 Privileges Required:
# N (None):   No authentication required
# L (Low):    Requires any authenticated user account
# H (High):   Requires admin or elevated privileges

# CVSS v3.1 Scope:
# U (Unchanged): The attack stays within the vulnerable component's security scope
# C (Changed):   The attack crosses into a different security scope (e.g. guest → host VM escape)

# Context beats score: a 7.2 on a production internet-facing server is more urgent
# than a 9.8 in an isolated lab with no internet exposure and no sensitive data.
# CVSS measures the vulnerability in isolation; environmental context adjusts real risk.

# Credentialed vs non-credentialed scans:
# Non-credentialed: scanner connects as an external, unauthenticated host
#   - May produce false positives from version-based detection
#   - Cannot check patch state, file contents, or registry
# Credentialed: scanner logs in and checks installed packages, patch state, configs
#   - Fewer false positives, more accurate remediation guidance
#   - Requires providing read-only credentials to the scanner
```

---

## 📌 About This Project

This repository represents the analytical layer on top of the automated scanning performed in Day 08. Running a vulnerability scanner produces output; interpreting that output is the actual skill.

The CVSS vector breakdown work demonstrates something specific: understanding why a score is what it is, not just what number it returned. An analyst who can explain that CVE-2011-2523 scores 9.8 because it's network-accessible, requires no privileges, and completely compromises the system is telling a fundamentally different story than one who reads "9.8 Critical" and moves on. That explanation is what makes findings useful to non-technical stakeholders who need to understand business risk, not just scores.

The false positive analysis reinforces another professional expectation: scanner output is not ground truth. It's a starting point that requires verification, especially for version-based detections on Linux packages where distributions backport fixes without changing version strings.

**Related repositories (in order):**

- `OpenVAS-GVM-Vulnerability-Scan`: The source scan — Day 08 Full and Fast results that this lab interprets in depth
- `Service-Version-Detection-and-OS-Fingerprinting`: Manual NVD research in Week 1 built the same CVE lookup skill used here; Day 09 applies that skill at scale against full scan output
- `Nmap-Scripting-Engine`: Live exploitation of CVE-2011-2523 (vsftpd backdoor) confirmed the #1-ranked finding in this prioritization exercise
- `Recon-Assessment-Report`: Week 1 assessment providing the baseline risk picture that this scanner expands on

---

## 👤 Author

**Dashane James**  
Senior Field Service Technician → Cybersecurity Analyst  
📍 Yonkers, NY  
🎓 B.S. Information Technology, SUNY Canton  
🏆 CompTIA Security+  
🔗 [GitHub](https://github.com/Dashanejames1) | [Zero Trust Cyber Security Brand](https://www.instagram.com/zerotrust_cybersecurity)

---

*This repository is part of an active portfolio demonstrating hands-on cybersecurity skills. All lab work performed in isolated environments for educational purposes.*
