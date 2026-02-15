SOC Investigation README

Investigation Summary:
I investigated a critical SOC342 alert involving a zero-day vulnerability known as ToolShell (CVE-2025-53770) targeting an on-premises Microsoft SharePoint server. I analyzed web, proxy, endpoint, and application-layer telemetry and confirmed unauthenticated remote code execution via a malicious POST request to the ToolPane.aspx endpoint. Post-exploitation analysis revealed extensive use of Living-off-the-Land binaries, including cmd.exe, powershell.exe, and csc.exe, to decode payloads, compile malicious executables, and extract ASP.NET MachineKey secrets. I identified the deployment of a persistent ASPX web shell within the SharePoint LAYOUTS directory, confirming full system compromise. I assessed the impact as critical, validated the incident as a true positive zero-day breach, and documented containment, remediation, and forensic recommendations.

Skills Used:
- Tier 3 SOC Incident Investigation
- Zero-Day Vulnerability & CVE Analysis
- SharePoint & Web Application Security
- Remote Code Execution (RCE) Detection
- Endpoint Telemetry & Process Analysis
- PowerShell & C# Payload Decoding
- Living-off-the-Land (LOLBins) Detection
- Threat Intelligence & IP Reputation Analysis
- Persistence Mechanism Identification
- Incident Containment & Escalation
- Risk & Impact Assessment
- Security Documentation & Executive Reporting
