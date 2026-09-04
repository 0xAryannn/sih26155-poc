# SIH 26155 — AI-Driven Network Security Compliance Auditor

## Overview

A Proof of Concept (POC) for **SIH Problem Statement 26155**.

The system analyzes network device configuration files, identifies security issues, detects unknown configuration syntax, and generates a security score with evidence.

## Current MVP

The current MVP supports:

- Network configuration file input
- Basic Cisco configuration parsing
- Security/compliance checks
- Unknown configuration detection
- Administrator-guided learning
- Persistent learned mappings using `learned.json`
- Findings with severity and configuration evidence
- Security score (0–100)
- Risk classification
- JSON audit report generation

## Current Workflow

```text
Configuration File
        ↓
Configuration Loader
        ↓
Parser
        ↓
Known / Learned / Unknown
        ↓
Security Checks
        ↓
Findings + Evidence
        ↓
Security Score
        ↓
Risk Level
        ↓
audit_report.json
````

## Adaptive Learning

When the system encounters unfamiliar configuration syntax, an administrator can teach it what the syntax represents.

```text
Unknown Syntax
      ↓
Administrator Training
      ↓
learned.json
      ↓
Future Recognition
      ↓
Compliance Evaluation
```

## Example

```text
Security Score: 10/100
Risk Level: CRITICAL
```

The auditor also reports the configuration evidence responsible for each finding.

## Current Scope

The present POC uses a small set of simplified security rules and primarily demonstrates Cisco configuration syntax.

These rules are for MVP validation and are **not yet a complete CIS, NIST, STIG, or ISO implementation**.

## Next Phase

Planned enhancements:

* LLM-assisted interpretation of unknown syntax
* Vendor-neutral normalization
* Multi-vendor support
* CIS / NIST / STIG / ISO mapping
* Advanced verification
* Dashboard and reporting

## Project Structure

```text
sih26155-poc/
├── auditor.py
├── config_loader.py
├── run_audit.py
├── learned.json
├── audit_report.json
└── configs/
```

**Current status: Core MVP / POC working end-to-end.**

