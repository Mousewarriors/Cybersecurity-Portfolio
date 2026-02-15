CloudWatch Log Analysis – XSS Investigation README

Investigation Summary:
I conducted a CloudWatch log analysis to investigate suspicious web requests targeting the endpoint /VA/trick.php. I imported raw HTTP access logs into LibreOffice for structured analysis, normalized timestamps, and filtered requests originating from a single external IP address (217.131.121.78). By correlating timestamps and request patterns, I identified the first malicious payload at 03/Oct/2023 20:58:54, marking the start of the attack. Detailed inspection of query parameters revealed repeated payload mutations targeting the vulnerable 'name' parameter, including URL-encoded JavaScript alert payloads. The activity demonstrated systematic probing and payload evolution consistent with reflected Cross-Site Scripting (XSS) exploitation attempts rather than benign traffic. I confirmed the attack type, source IP, affected parameter, and attack timeline, completing the investigation with validated answers and documented findings.

Skills Used:
- CloudWatch Log Analysis
- Web Server Log Parsing & Normalization
- Incident Timeline Reconstruction
- Web Application Security Analysis
- Cross-Site Scripting (XSS) Detection
- URL & Payload Decoding
- Threat Hunting & Pattern Analysis
- IOC Identification (IP, Parameter, Payload)
- Data Analysis Using LibreOffice
- Evidence-Based Incident Validation
- SOC Analyst Investigation Methodology
