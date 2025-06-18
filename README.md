# **RedLine Stealer Malware Investigation - SOC Threat Intelligence**

## **Overview**
This repository contains the results of an investigation into a suspicious executable file, suspected to be linked to the **RedLine Stealer** malware. The investigation was conducted as part of a Threat Intelligence exercise within the **Security Operations Center (SOC)**. 

The goal was to analyze the file’s hash, gather intelligence using various threat analysis tools, and provide valuable insights to assist the **Incident Response** team.

## **Investigation Tools**
The following tools were utilized during the investigation:

- **VirusTotal**: Malware scanning and analysis platform for understanding file behavior.
- **ANY.RUN**: Interactive malware sandbox for detailed dynamic analysis, including DNS queries, network activity, and behavior logs.
- **MalwareBazaar**: Malware sample repository for YARA rules and associated threat intelligence.
- **ThreatFox**: A platform for analyzing and tracking threat actor infrastructure, including IP addresses and domains.
- **Whois**: Tool for identifying ownership information related to malicious domains and IP addresses.

## **Investigation Findings**

### **1. Malware Category**
- **Answer**: Trojan  
- **Details**: The malware was identified as a Trojan, which disguises itself as a legitimate program to gain unauthorized access to the system.  
- **Link**: [VirusTotal Analysis](https://www.virustotal.com/gui/file/248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b)

### **2. File Name**
- **Answer**: WEXTRACT  
- **Details**: The file identified by its hash corresponds to the name "WEXTRACT." This file is suspected to be a Trojan posing as a legitimate tool.

### **3. First Submission Timestamp**
- **Answer**: 2023-10-06 04:41 UTC  
- **Details**: The malware was first submitted to VirusTotal on this timestamp, indicating its initial discovery.

### **4. MITRE ATT&CK Technique (Data Collection)**
- **Answer**: T1005 (Data from Local System)  
- **Details**: The malware uses this technique to collect sensitive data from the local system, likely preparing it for exfiltration.

### **5. Social Media Domain**
- **Answer**: facebook.com  
- **Details**: The malware resolved the domain `facebook.com` via DNS queries, potentially used for social engineering or additional activities.

### **6. IP Address and Port Communication**
- **Answer**: 77.91.124.55:19071  
- **Details**: The malware communicated with this IP address and port, crucial for detecting and blocking future attempts.

### **7. YARA Rule for Detection**
- **Answer**: [detect_Redline_Stealer](https://bazaar.abuse.ch/sample/248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b#intel)  
- **Details**: The YARA rule created by "Varp0s" can detect the **RedLine Stealer** malware.

### **8. Malware Alias (ThreatFox)**
- **Answer**: RECORDSTEALER  
- **Details**: According to ThreatFox, the malware is also known by the alias **RECORDSTEALER**.

### **9. Privilege Escalation (DLL)**
- **Answer**: ADVAPI32.dll  
- **Details**: The malware utilized **ADVAPI32.dll**, a Windows system DLL, to escalate privileges on the infected system.

## **Conclusion**
This investigation into **RedLine Stealer** highlights the importance of using a multi-tool approach in identifying malware, understanding its behavior, and gathering indicators of compromise (IOCs). 

By utilizing **VirusTotal, ANY.RUN, MalwareBazaar, ThreatFox**, and other intelligence platforms, a comprehensive understanding of the malware’s tactics, techniques, and procedures (TTPs) was achieved. This process aids the SOC in better protecting the organization against such threats.

### **Key Takeaways:**
- **Malware Analysis**: A comprehensive approach helps to identify the malware’s behavior, impact, and attack vector.
- **Cross-referencing Data**: Using multiple tools provides a more complete picture of the threat.
- **Proactive Threat Intelligence**: Sharing findings with incident response teams improves incident management and overall cybersecurity posture.

<!-- GitAds-Verify: 5TS8CM8IMO2GTGYVLUZF7WWYD751HYAM -->

## **Resources**
- [VirusTotal](https://www.virustotal.com)
- [ANY.RUN](https://any.run)
- [MalwareBazaar](https://bazaar.abuse.ch)
- [ThreatFox](https://threatfox.abuse.ch)

---
## GitAds Sponsored
[![Sponsored by GitAds](https://gitads.dev/v1/ad-serve?source=coderblee/red-stealer-lab@github)](https://gitads.dev/v1/ad-track?source=coderblee/red-stealer-lab@github)

