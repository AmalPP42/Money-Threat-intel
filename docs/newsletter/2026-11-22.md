# 🛡️ Daily Threat Intel — November 22, 2026

> **Automated daily briefing** covering the most critical cybersecurity 
> threats from 9 leading security news sources.

---

## 📊 Analyst Briefing

📊 15 threats detected today.
🔴 CRITICAL (7): Researchers Demonstrate Ghostscript Sandbox-Escape RCE via Crafted File Uploads in Popular Apps | GnuPG Warns Critical GPGME Flaw Could Expose App Data via Malicious OpenPGP Keys | Attackers' AI Agents Found a Zero-Day in Medical-Imaging Software and Gained Root Access
🟠 HIGH (6): WhatsApp Patches 3 Security Flaws, Including Android Bug Suspected of Use in Scams | Rackspace Spot breach let hackers access customer Kubernetes secrets | Microsoft Entra Connect Health flaw exploited to steal tenant data
⚠️ Review all articles below and patch accordingly.

---

## 🔍 Top Threats

### 🔴 Researchers Demonstrate Ghostscript Sandbox-Escape RCE via Crafted File Uploads in Popular Apps

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: rce
- **Link**: [https://thehackernews.com/2026/11/researchers-demonstrate-ghostscript.html](https://thehackernews.com/2026/11/researchers-demonstrate-ghostscript.html)

A now-patched flaw in Ghostscript allows a crafted file to escape the program's security sandbox and run commands on the server that processes it.

Ghostscript is the interpreter that many Linux servers use to convert uploaded PDFs, PostScript files, and images into other formats, often without the 

---

### 🔴 GnuPG Warns Critical GPGME Flaw Could Expose App Data via Malicious OpenPGP Keys

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: —
- **Keywords**: cve-
- **Link**: [https://thehackernews.com/2026/11/gnupg-warns-critical-gpgme-flaw-could.html](https://thehackernews.com/2026/11/gnupg-warns-critical-gpgme-flaw-could.html)

A malicious OpenPGP key with an unusually long user ID can trigger a critical memory bug in GPGME, the standard library that programs use to work with GnuPG.

The GnuPG project warned yesterday that the flaw could be used to steal data from affected applications and has released fixed versions.

The

---

### 🔴 Attackers' AI Agents Found a Zero-Day in Medical-Imaging Software and Gained Root Access

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: zero-day, rce
- **Link**: [https://thehackernews.com/2026/11/attackers-ai-agents-found-zero-day-in.html](https://thehackernews.com/2026/11/attackers-ai-agents-found-zero-day-in.html)

Suspected China-linked hackers used autonomous AI agents to find a previously unknown flaw in MONAI Label, an open-source medical imaging server, and gain root access to a university server, Amazon Threat Intelligence said this week.

The flaw allows an attacker with no account to write files outsid

---

### 🔴 Hackers Exploit Critical VMware, Cisco, and Apache Flaws as Espionage Attacks Emerge

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Initial Access
- **Keywords**: exploit, vulnerability, cve-
- **Link**: [https://thehackernews.com/2026/11/hackers-exploit-critical-vmware-cisco.html](https://thehackernews.com/2026/11/hackers-exploit-critical-vmware-cisco.html)

The U.S. Cybersecurity and Infrastructure Security Agency (CISA) on Friday added four flaws impacting Apache Roller, Cisco Expressway, SAP NetWeaver, and Broadcom VMware vCenter to its Known Exploited Vulnerabilities (KEV), citing evidence of active exploitation.

The vulnerabilities are listed belo

---

### 🔴 FBI reportedly hacked again, this time targeting nationwide police database

- **Source**: BleepingComputer
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: breach, rce
- **Link**: [https://www.bleepingcomputer.com/news/security/fbi-reportedly-hacked-again-this-time-targeting-nationwide-police-database/](https://www.bleepingcomputer.com/news/security/fbi-reportedly-hacked-again-this-time-targeting-nationwide-police-database/)

FBI systems have reportedly been breached for the second time in two months, this time targeting the agency's National Crime Information Center (NCIC), which is used to share information between local, state, and federal law enforcement agencies. [...]

---

### 🔴 Hackers use autonomous AI tool Cairn to find zero-day, take over server

- **Source**: BleepingComputer
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: zero-day, vulnerability, rce
- **Link**: [https://www.bleepingcomputer.com/news/security/hackers-use-autonomous-ai-tool-cairn-to-find-zero-day-take-over-server/](https://www.bleepingcomputer.com/news/security/hackers-use-autonomous-ai-tool-cairn-to-find-zero-day-take-over-server/)

Threat actors used the open-source AI penetration-testing framework Cairn to find a previously unknown vulnerability in a medical imaging application. [...]

---

### 🔴 China's 'Armory Castle' Lays Siege to VMware vCenter Zero-Day

- **Source**: Dark Reading
- **Severity**: CRITICAL
- **MITRE Tactics**: —
- **Keywords**: zero-day
- **Link**: [https://www.darkreading.com/cyberattacks-data-breaches/china-armory-castle-vmware-vcenter-zero-day](https://www.darkreading.com/cyberattacks-data-breaches/china-armory-castle-vmware-vcenter-zero-day)

During the last wave of major VMware vCenter security updates, a China-nexus threat group likely already had its next zero-day up its sleeve.

---

### 🟠 WhatsApp Patches 3 Security Flaws, Including Android Bug Suspected of Use in Scams

- **Source**: The Hacker News
- **Severity**: HIGH
- **MITRE Tactics**: Initial Access
- **Keywords**: exploit, vulnerability, cve-
- **Link**: [https://thehackernews.com/2026/11/whatsapp-patches-3-security-flaws.html](https://thehackernews.com/2026/11/whatsapp-patches-3-security-flaws.html)

Meta-owned WhatsApp has addressed security vulnerabilities, including one impacting its Android app that it suspects may have been exploited in connection with scam messages.

The vulnerability, tracked as CVE-2026-23871 (CVSS score: 3.5), has been described as a case of incomplete validation of ext

---

### 🟠 Rackspace Spot breach let hackers access customer Kubernetes secrets

- **Source**: BleepingComputer
- **Severity**: HIGH
- **MITRE Tactics**: Initial Access, Credential Access
- **Keywords**: breach, credential
- **Link**: [https://www.bleepingcomputer.com/news/security/rackspace-spot-breach-let-hackers-access-customer-kubernetes-secrets/](https://www.bleepingcomputer.com/news/security/rackspace-spot-breach-let-hackers-access-customer-kubernetes-secrets/)

Rackspace warned customers that hackers breached its Rackspace Spot cloud platform using compromised credentials, allowing them to deploy unauthorized workloads and access Kubernetes secrets in customer clusters. [...]

---

### 🟠 Microsoft Entra Connect Health flaw exploited to steal tenant data

- **Source**: BleepingComputer
- **Severity**: HIGH
- **MITRE Tactics**: Initial Access
- **Keywords**: breach, exploit, vulnerability
- **Link**: [https://www.bleepingcomputer.com/news/security/microsoft-entra-connect-health-flaw-exploited-to-steal-tenant-data/](https://www.bleepingcomputer.com/news/security/microsoft-entra-connect-health-flaw-exploited-to-steal-tenant-data/)

Microsoft is warning organizations that it suffered a data breach after attackers exploited a vulnerability in its Entra Connect Health service to gain unauthorized access to administrator email addresses and tenant configuration information. [...]

---
