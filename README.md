# **Zeek Network Forensics Lab**

## 💑 **Table of Contents**
- [Description](#description)
- [Tools and Technologies Used](#tools-and-technologies-used)
- [Environment](#environment)
- [Task Instructions](#task-instructions)
- [My Investigation Steps](#my-investigation-steps)
  - [Case 1 - Anomalous DNS](#case-1---anomalous-dns)
  - [Case 2 - Phishing Attempt](#case-2---phishing-attempt)
  - [Case 3 - Log4J Exploitation](#case-3---log4j-exploitation)
- [Conclusion](#conclusion)

---

## **Description**
This project explores network forensics using **Zeek** as part of a TryHackMe challenge. The exercise involves investigating three real-world alert scenarios using `.pcap` data and Zeek log analysis. Threats include:
- DNS tunneling
- Phishing file delivery
- Remote code execution via Log4Shell (CVE-2021-44228)

---

## **Tools and Technologies Used**
- **Zeek Network Monitor**
- **VirusTotal**
- **Linux Command Line Utilities (awk, sort, uniq, base64, etc.)**
- **PCAP files & Zeek log files**

---

## **Environment**
- **Operating System**: Ubuntu 22.04
- **Lab Platform**: TryHackMe Zeek Room
- **PCAP Files**: `dns-tunneling.pcap`, `phishing.pcap`, `log4shell.pcapng`

---

## **Task Instructions**

### General Process:
1. Load PCAP files using Zeek.
2. Examine relevant logs (e.g., `conn.log`, `dns.log`, `http.log`, `files.log`, `signatures.log`).
3. Extract key indicators (IP addresses, domains, file hashes, etc.).
4. Decode any obfuscated or encoded payloads (e.g., base64).
5. Validate artifacts using VirusTotal where necessary.

---

## **My Investigation Steps**

### 🔍 Case 1 - Anomalous DNS
> **Alert:** Anomalous DNS Activity

#### 🛠 Step 0: Generate Logs
```bash
zeek -C -r dns-tunneling.pcap
```

#### 🔹 Step 1: Analyze DNS Query Types
```bash
zeek-cut qtype_name < dns.log | sort | uniq -c
```
- **Result:** `320` AAAA records  
- `![A1.jpg](./images/A1.jpg)`

#### 🔹 Step 2: Find Longest Connection
```bash
zeek-cut duration < conn.log | sort -r | head -n 1
```
- **Result:** `9.420791` seconds  
- `![A2.jpg](./images/A2.jpg)`

#### 🔹 Step 3: Identify the Source Host
```bash
zeek-cut id.orig_h < conn.log | sort | uniq
```
- **Result:** `10.20.57.3`  
- `![A4.jpg](./images/A4.jpg)`

---

### 🧪 Case 2 - Phishing Attempt
> **Alert:** Phishing Activity Detected

#### 🛠 Step 0: Generate Logs
```bash
zeek -C -r phishing.pcap
```

#### 🔹 Step 1: Identify Suspicious Source IP
```bash
zeek-cut id.orig_h < conn.log | sort | uniq -c
```
- **Result:** `10[.]6[.]27[.]102`  
- `![1a.jpg](./images/1a.jpg)`

#### 🔹 Step 2: Identify Malicious Domain
```bash
zeek-cut host uri < http.log | sort | uniq
```
- **Result:** `smart-fax[.]com`  
- `![2.jpg](./images/2.jpg)`
- `![3.jpg](./images/3.jpg)`
- `![3a.jpg](./images/3a.jpg)`
- `![3b.jpg](./images/3b.jpg)`

#### 🔹 Step 3: Analyze Malicious Document (VirusTotal)
- **File Type:** `VBA`
- `![4.jpg](./images/4.jpg)`

#### 🔹 Step 4: Name of Malicious Executable
- **Result:** `PleaseWaitWindow.exe`
- `![5.jpg](./images/5.jpg)`

#### 🔹 Step 5: Contacted C2 Domain
- **Result:** `hopto[.]org`
- `![last.jpg](./images/last.jpg)`

---

### 💥 Case 3 - Log4J Exploitation
> **Alert:** Log4Shell RCE Attempt

#### 🛠 Step 0: Generate Logs with Custom Signature Script
```bash
zeek -C -r log4shell.pcapng detection-log4j.zeek
```

#### 🔹 Step 1: Count Signature Hits
```bash
zeek-cut uid < signatures.log | wc -l
```
- **Result:** `3`
- `![S1.jpg](./images/S1.jpg)`

#### 🔹 Step 2: Detect Scanning Tool
```bash
zeek-cut user_agent < http.log | sort | uniq -c
```
- **Result:** `Nmap`
- `![S2.jpg](./images/S2.jpg)`

#### 🔹 Step 3: Identify Exploit File Extension
```bash
zeek-cut uri < http.log | sort | uniq -c
```
- **Result:** `.class`
- `![S3.jpg](./images/S3.jpg)`

#### 🔹 Step 4: Decode Malicious Payload
```bash
echo "<base64-string>" | base64 -d
```
- **Result:** File created named `pwned`
- `![S4.jpg](./images/S4.jpg)`

---

## ✅ **Conclusion**

This lab demonstrates:
- Realistic Blue Team workflows using **Zeek**
- Hands-on skills in **detecting DNS tunneling**, **tracking phishing downloads**, and **decoding Log4j payloads**
- Practical investigation steps using **base64 decoding**, **log parsing**, and **threat intelligence lookup (VirusTotal)**

> 📌 Zeek is a powerful tool for defenders, and mastering its logs offers deep visibility into network behavior and threats.
