SOC127 Summary

Summary:
I investigated a high-severity SOC127 alert and confirmed it was a true positive SQL injection attack. I reviewed web and proxy logs and identified automated exploitation attempts using sqlmap from an external IP (118.194.247.28). I analyzed multiple malicious payloads, including boolean-based, UNION-based, and error-based SQL injection, along with XSS injection and attempted OS command execution. Consistent HTTP 200 responses and uniform response sizes confirmed successful SQL execution, indicating the application was vulnerable. I enriched the source IP with threat intelligence and confirmed it had a malicious reputation with no legitimate business relationship. I verified the traffic was external to internal, assessed the attack as successful and high risk, determined escalation was required, contained the affected server, completed playbook actions, and closed the alert with detailed analyst notes and remediation recommendations.

Skills Used:
- Security Monitoring & Alert Triage
- Incident Investigation & Analysis (Tier 2–3 SOC)
- SQL Injection Detection & Analysis
- Web Application Security Analysis
- Log Analysis (Web, Proxy, HTTP logs)
- Threat Intelligence & IP Reputation Analysis
- Malicious Payload Decoding & URL Decoding
- Attack Chain & Kill Chain Analysis
- Tool Identification (sqlmap fingerprinting)
- Traffic Direction & Network Analysis
- True Positive / False Positive Determination
- Risk & Impact Assessment
- Containment & Incident Response
- Playbook Execution
- Root Cause Analysis
- Security Documentation & Analyst Reporting
- Vulnerability Identification & Exploit Validation
- Incident Severity Classification & Escalation
