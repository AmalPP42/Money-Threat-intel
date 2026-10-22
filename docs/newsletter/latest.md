# 🛡️ Daily Threat Intel — October 22, 2026

> **Automated daily briefing** covering the most critical cybersecurity 
> threats from 9 leading security news sources.

---

## 📊 Analyst Briefing

📊 15 threats detected today.
🔴 CRITICAL (8): Node.js Brotli Decoder Bug Could Allow Remote Code Execution in All Supported Versions | New QPACK Flaws Can Crash HTTP/3 Servers, Trigger Up to 4,000-Fold Memory Amplification | Someone Tried to Exploit PHP2Shell 4 Days Before the Vulnerabilities Were Publicly Disclosed
🟠 HIGH (5): LiteLLM Suspects GitHub Token Leak in AI Gateway Logs Behind Malicious Package Release | Japan's Onamae Desktop Cloud hacked, up to 27,000 servers affected | Lazarus hackers use post-quantum cryptography for malware delivery
⚠️ Review all articles below and patch accordingly.

---

## 🔍 Top Threats

### 🔴 Node.js Brotli Decoder Bug Could Allow Remote Code Execution in All Supported Versions

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: remote code execution
- **Link**: [https://thehackernews.com/2026/10/nodejs-brotli-decoder-bug-could-allow.html](https://thehackernews.com/2026/10/nodejs-brotli-decoder-bug-could-allow.html)

Node.js released&nbsp;security updates&nbsp;on October 21 for its three supported release lines, 22.x, 24.x and 26.x, fixing 10 flaws. The most serious is a bug in the Brotli decompression code that Node.js bundles, which the project says can allow remote code execution, meaning an attacker could ru

---

### 🔴 New QPACK Flaws Can Crash HTTP/3 Servers, Trigger Up to 4,000-Fold Memory Amplification

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: rce
- **Link**: [https://thehackernews.com/2026/10/new-qpack-flaws-can-crash-http3-servers.html](https://thehackernews.com/2026/10/new-qpack-flaws-can-crash-http3-servers.html)

A remote attacker who has not logged in can crash many HTTP/3 web servers with a single connection, security firm FoxIO&nbsp;disclosed, releasing working proof-of-concept code.

By sending a small batch of compressed HTTP headers that expands in memory to a much larger set, the attacker can force th

---

### 🔴 Someone Tried to Exploit PHP2Shell 4 Days Before the Vulnerabilities Were Publicly Disclosed

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Initial Access
- **Keywords**: exploit
- **Link**: [https://thehackernews.com/2026/10/someone-tried-to-exploit-php2shell-4.html](https://thehackernews.com/2026/10/someone-tried-to-exploit-php2shell-4.html)

Amazon's Threat Intelligence team on Wednesday said it detected an attempt to exploit the newly disclosed PHP2Shell vulnerabilities on October 17, 2026, against its MadPot honeypot service, as the flaws come under broad exploitation in the wild following the release of the patches.

"The exploit att

---

### 🔴 China-Linked Hackers Use ARTEX AI Agents in ConnectWise Supply Chain Attack

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Initial Access, Execution
- **Keywords**: rce, supply chain
- **Link**: [https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html](https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html)

Microsoft on Wednesday disclosed that a China state-aligned actor dubbed Storm-0940 was behind the recent supply chain compromise of the ConnectWise Cloud Backup application.

During the incident, Storm-0940 used ARTEX, a Go-based agentic AI penetration testing framework that was made closed-source 

---

### 🔴 Critical GitLab Flaw (CVSS 10.0) Could Allow Unauthenticated RCE Across 12 Years of Releases

- **Source**: The Hacker News
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: rce
- **Link**: [https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html](https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html)

GitLab released fixes on October 21 for a flaw that lets an attacker run code on a self-managed server without logging in, and it affects every version of the software going back to 7.0, released in 2014.

The fix matters even for administrators who patched nine days earlier: the October 12 update c

---

### 🔴 Authorities disrupt nearly 11,000 cybercrime networks in Africa

- **Source**: BleepingComputer
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution, Impact
- **Keywords**: ransomware, rce
- **Link**: [https://www.bleepingcomputer.com/news/security/authorities-disrupt-nearly-11-000-cybercrime-networks-in-africa/](https://www.bleepingcomputer.com/news/security/authorities-disrupt-nearly-11-000-cybercrime-networks-in-africa/)

Law enforcement agencies have disrupted nearly 11,000 cybercriminal networks and arrested more than 1,400 people in Operation Serengeti III, which targeted business email compromise, ransomware, and online scams. [...]

---

### 🔴 PHP ships emergency patches for critical PHP2Shell flaws

- **Source**: BleepingComputer
- **Severity**: CRITICAL
- **MITRE Tactics**: Execution
- **Keywords**: cve-, remote code execution, rce
- **Link**: [https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/](https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/)

The PHP security team released emergency security patches for two critical remote code execution (RCE) vulnerabilities (CVE-2026-109618 and CVE-2026-109619) tracked collectively as PHP2Shell. [...]

---

### 🔴 'PHP2Shell' Bugs Signal Red Alert for Security Industry

- **Source**: Dark Reading
- **Severity**: CRITICAL
- **MITRE Tactics**: Initial Access
- **Keywords**: exploit
- **Link**: [https://www.darkreading.com/application-security/php2shell-bugs-red-alert-security-industry](https://www.darkreading.com/application-security/php2shell-bugs-red-alert-security-industry)

Security teams are scrambling to remediate two critical PHP vulnerabilities following leaked details and reports of exploitation attempts.

---

### 🟠 LiteLLM Suspects GitHub Token Leak in AI Gateway Logs Behind Malicious Package Release

- **Source**: The Hacker News
- **Severity**: HIGH
- **MITRE Tactics**: Initial Access, Persistence, Credential Access
- **Keywords**: backdoor, credential
- **Link**: [https://thehackernews.com/2026/10/litellm-suspects-github-token-leak-in.html](https://thehackernews.com/2026/10/litellm-suspects-github-token-leak-in.html)

LiteLLM on Wednesday disclosed that threat actors compromised "multiple independent security controls" to push a malicious version of the Python package containing a credential stealer and a backdoor.

On October 21, 2026, LiteLLM's release pipeline was compromised to push 1.107.0 to the Docker Hub 

---

### 🟠 Japan's Onamae Desktop Cloud hacked, up to 27,000 servers affected

- **Source**: BleepingComputer
- **Severity**: HIGH
- **MITRE Tactics**: Execution
- **Keywords**: malware
- **Link**: [https://www.bleepingcomputer.com/news/security/japans-onamae-desktop-cloud-hacked-up-to-27-000-servers-affected/](https://www.bleepingcomputer.com/news/security/japans-onamae-desktop-cloud-hacked-up-to-27-000-servers-affected/)

Hackers compromised the infrastructure of Onamae Desktop Cloud, a popular provider of VPS services in Japan, and installed malware on up to 26,739 customers' servers. [...]

---
