Enterprise Detection & Attack Simulation Lab - README

Lab Overview:
I designed, built, and configured a fully isolated enterprise-style cybersecurity lab to support detection engineering, SOC investigations, attack simulation, and malware analysis. The lab consists of a centralized Splunk Enterprise SIEM, a Windows Server Active Directory domain controller, a Windows 10 domain-joined endpoint, a Kali Linux attack platform, and a FLARE VM malware analysis workstation. All systems are networked, instrumented, and operational, enabling end-to-end attack detection and response workflows.

What I Built & Configured:
I deployed Splunk Enterprise as a centralized logging and analysis platform and ingested endpoint telemetry from Windows systems, including Sysmon and Windows Event Logs. I configured custom SPL searches to extract process creation, network connections, and authentication events. I built a Windows Server Active Directory environment, created organizational units, users (HR and IT), and managed domain authentication. I joined the Windows 10 endpoint to the domain and validated log generation for authentication, process execution, and network activity.

I configured Kali Linux as an attacker workstation with offensive tooling for reconnaissance and exploitation testing. I deployed a FLARE VM with an extensive malware analysis toolkit, installed via Chocolatey, including reverse engineering, debugging, memory analysis, and forensic utilities. I validated the environment by executing controlled activities, monitoring telemetry in Splunk, and confirming visibility across the entire attack lifecycle.

Skills Used:
- Enterprise Lab Architecture & Virtualization
- Windows Server & Active Directory Administration
- Domain User & Group Management
- Endpoint Telemetry & Sysmon Configuration
- Splunk Enterprise Deployment & SPL Querying
- SIEM Data Ingestion & Parsing
- Network Segmentation & Lab Networking
- Attack Simulation with Kali Linux
- Malware Analysis Environment Setup (FLARE VM)
- Reverse Engineering & Forensics Tooling
- Detection Engineering & Threat Hunting
- SOC Analyst & Blue Team Workflows
- Incident Visibility & Telemetry Validation
- Documentation & Lab Hardening

Use Case:
This lab is designed for hands-on practice in SOC analysis, threat hunting, malware analysis, detection engineering, and red team / blue team experimentation. It supports real-world attack simulation, investigation workflows, and security research.
