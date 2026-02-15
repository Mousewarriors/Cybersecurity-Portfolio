MITRE ATT&CK Classification RAG Project - README

Project Overview:
I designed and tuned a local Large Language Model (LLM) integrated with Retrieval-Augmented Generation (RAG) to perform deterministic MITRE ATT&CK technique classification from security alerts and logs. The goal of this project was to accurately map observable alert evidence to ATT&CK techniques using only retrieved knowledge base context, avoiding hallucination or inference.

What I Did:
I curated and pre-processed a local MITRE ATT&CK knowledge base, filtering active, deprecated, and revoked techniques using official STIX metadata. I implemented a Python pipeline to split and validate technique markdown files, ensuring only valid techniques were indexed for retrieval. I engineered strict system prompts enforcing evidence-only classification rules and integrated the knowledge base into a RAG workflow using Open WebUI. I tuned model parameters (temperature, top-p, context size) to maximize determinism and reproducibility. I validated the system using real EDR, Sysmon, and process-monitoring alerts, successfully identifying techniques such as Native API, Process Injection, PowerShell, System Information Discovery, and C2 communication with confidence scoring.

Skills Used:
- MITRE ATT&CK Framework Mastery
- Detection Engineering
- Retrieval-Augmented Generation (RAG)
- Prompt Engineering for Security Use Cases
- Local LLM Tuning & Evaluation
- Threat Intelligence Knowledge Curation
- Python Automation & Scripting
- STIX / ATT&CK Data Handling
- EDR & Sysmon Log Analysis
- Evidence-Based Threat Classification
- AI Safety & Hallucination Mitigation
- SOC Analyst Workflow Automation
