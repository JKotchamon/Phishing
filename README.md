# 🛡️ Phishing Email Analysis Toolkit

This project provides an overview and resources for understanding, analyzing, and defending against phishing attacks. It is designed to help cybersecurity learners and practitioners investigate phishing emails, understand their techniques, and apply various tools to analyze and mitigate threats.

---

## 1️⃣ What is a Phishing Email?

Phishing is a type of cyber attack where attackers trick users into revealing sensitive information or downloading malicious software through deceptive emails. These emails often appear to be from legitimate sources and aim to exploit human psychology.

### 1.1 How Phishing Works (Psychological Triggers)
- **Authority**: Pretending to be someone in power (e.g., CEO, government).
- **Trust**: Impersonating trusted entities like banks or coworkers.
- **Intimidation**: Threats of account suspension or legal action.
- **Urgency**: Demanding quick action to avoid consequences.
- **Scarcity**: Limited-time offers to lure immediate response.
- **Social Proof**: Claims that others have taken the same action.
- **Familiarity**: Using names or contexts the victim recognizes.

---

## 2️⃣ Email Fundamentals: How Email Works

Understanding the path of email helps in tracing and analyzing attacks:

Sender → Sender's Mail Server → Recipient's Mail Server → Recipient

Each step can be inspected for anomalies when analyzing a suspicious email.

---

## 3️⃣ Types of Phishing Attacks

- **Information Gathering**: Collecting user details for future use.
- **Credential Harvesting**: Fake login pages to steal credentials.
- **Malware Delivery**: Attachments or links that install malware.
- **Spear Phishing**: Targeted phishing using personal info.
- **Whaling**: Targeting high-profile individuals like executives.
- **Vishing**: Voice phishing via phone calls.
- **Smishing**: SMS-based phishing attacks.

---

## 4️⃣ Phishing Attack Techniques

- **Pretexting**: Fabricated scenario to get information.
- **Spoofing**: Forging email headers to appear trusted.
- **Encoding**: Obfuscating content to evade detection.
- **URL Manipulation**: Lookalike URLs, hidden redirects.
- **Attachments**: Malicious file types (e.g., .exe, .docm).
- **Abuse of Legitimate Services**: Hosting payloads on Dropbox, Google Drive, etc.

---

## 5️⃣ Email Header Analysis

When analyzing a suspicious email, look at:

### 🔍 Key Elements to Analyze:

- **📅 Date and Time**: When was the email sent?
- **📨 Subject Line**: Is it misleading or overly urgent?
- **👥 Recipient**: Was it sent to a large group or a specific person?
- **👤 Claimed Sender vs Real Sender**: Do the display name and email address match?
- **📧 Return Path / From Address**: Check for discrepancies or lookalike domains.
- **🔐 Authentication Results**:
  - **SPF (Sender Policy Framework)** – validates sending IP
  - **DKIM (DomainKeys Identified Mail)** – verifies message integrity
  - **DMARC (Domain-based Message Authentication, Reporting, and Conformance)** – alignment of SPF and DKIM
- **📝 Email Body**:
  - Is the tone urgent or threatening?
  - Are there grammar or spelling errors?
  - Does it request credentials or personal info?
- **🔗 URL Links & Attachments**:
  - Are there shortened or suspicious links?
  - Are there unexpected attachments?

### 5.1 Useful Tools for Analysis

- 🔍 [Whois Domain Lookup](https://whois.domaintools.com/)
- 🔧 `nslookup -type=txt <domain> | grep -i spf` – Check SPF records
- 🧪 [CyberChef](https://gchq.github.io/CyberChef/) – Decode obfuscated content
- 🔗 [URLScan.io](https://urlscan.io/) – Scan and analyze URLs
- 🛡️ [VirusTotal](https://www.virustotal.com/gui/home/upload) – Analyze files and links
- 📡 [Talos Intelligence](https://talosintelligence.com/) – Domain/IP reputation

---
### 📨 Email Body & Header Decoding
- [CyberChef](https://gchq.github.io/CyberChef/)

### 🌐 URL and Link Analysis
- [urlscan.io](https://urlscan.io/)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [Cisco Talos Intelligence](https://talosintelligence.com/)

---

### 🧪 5.2 Dynamic Attachment Analysis and Sandboxing

Attachments may contain malicious scripts or executables. Use sandbox environments:

- [Hybrid Analysis](https://hybrid-analysis.com/)
- [ANY.RUN](https://app.any.run/)

---
### 🧪 5.3  Email Attachment Analysis and Static MalDoc Analysis 
Phishing emails often include malicious content such as email attachments or embedded objects. Use these open-source tools for analysis:

- [`emldump.py`](https://github.com/DidierStevens/DidierStevensSuite/blob/master/emldump.py) – for parsing `.eml` files and extracting email parts for inspection
- [`oledump.py`](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py) – for analyzing OLE files (like Word/Excel docs) for malicious macros or embedded content
- [`Email-IOC-Extractor`](https://github.com/MalwareCube/Email-IOC-Extractor) – for extracting indicators of compromise (IOCs) such as URLs, IPs, and hashes from email files
- 
---
### 📄 5.4 PDF File Analysis

Phishing emails often include malicious PDFs. Use these open-source tools:

- [`pdf-parser.py`](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py) — for analyzing structure and objects in PDF files  
- [`pdfid.py`](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py) — for identifying suspicious elements in PDF files

## 6️⃣ Phishing Defense Strategies

- **Email Filters**: Block spam and suspicious emails.
- **URL Scanning and Blocking**: Check links before opening.
- **Attachment Filters**: Block dangerous file types.
- **Email Authentication**: Enforce SPF, DKIM, and DMARC policies.
- **User Training**: Educate users to recognize phishing attempts.

---
