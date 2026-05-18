# M365 Security Assessment Framework

## Overview

This document outlines the security assessment methodology used by Secure Scale Systems Ltd when evaluating Microsoft 365 and Entra ID environments. Assessments are structured across five domains and measured against established industry benchmarks and regulatory frameworks.

---

## Assessment Domains

### 1. Identity Governance

Covers tenant configuration, administrator account hygiene, emergency access controls, and directory settings. Key controls evaluated include tenant branding, technical and privacy contacts, break-glass account configuration, and legacy authentication exposure.

### 2. Authentication Controls

Covers MFA enforcement, Conditional Access policy coverage, named location configuration, and legacy authentication blocking. Evaluated against the Microsoft Zero Trust identity baseline and CIS Microsoft 365 Foundations Benchmark controls.

### 3. Identity Protection

Covers Entra ID P2 Identity Protection configuration, user risk and sign-in risk policy deployment, risk detection baseline, and CA risk-based policy integration. Requires Entra ID P2 licensing.

### 4. Security Monitoring

Covers Microsoft Sentinel deployment, data connector configuration, Entra ID diagnostic settings, log ingestion validation, and workspace table availability. Assessed against the principle that every security control requires corresponding detection coverage.

### 5. Detection Engineering

Covers KQL threat hunting query library, Sentinel scheduled and NRT analytics rule deployment, MITRE ATT&CK coverage mapping, entity mapping configuration, and incident response readiness.

---

## Benchmark Alignment

| Framework | Version | Application |
|---|---|---|
| CIS Microsoft 365 Foundations Benchmark | v3.1.0 | Primary technical control baseline |
| Microsoft Zero Trust Maturity Model | Current | Identity and access architecture guidance |
| NIST Cybersecurity Framework | CSF 2.0 | Risk management and control categorisation |
| Nigeria Data Protection Regulation | NDPR 2019 | Data handling and privacy obligations |
| UK General Data Protection Regulation | UK GDPR | Data handling for UK-based entities |

---

## Severity Classification

| Severity | Definition | Target Remediation |
|---|---|---|
| Critical | Immediate risk of compromise | Emergency remediation |
| High | Significant exploitable risk | Within 7 days |
| Medium | Moderate risk or control gap | Within 30 days |
| Low | Minor gap or best-practice deviation | Within 90 days |
| Informational | No active risk, noted for awareness | No timeline required |

---

## Assessment Phases

**Phase 1 and 2: Baseline Hardening**
Tenant configuration review, Security Defaults evaluation, Sentinel deployment, data connector configuration, KQL query library development, and initial detection rule deployment.

**Phase 3: Risk-Adaptive Controls**
Entra ID P2 activation, Identity Protection deployment, Conditional Access policy framework (CA001 to CA005), named location configuration, SignInLogs ingestion validation, advanced KQL detection queries, and NRT analytics rule deployment.

**Ongoing: Continuous Improvement**
Authentication Methods migration, RoleManagementLogs enablement, detection rule enrichment with entity mapping and custom alert details, and periodic reassessment against updated CIS benchmarks.

---

## Key Operational Notes

**Break-glass account pattern:** Every assessment includes verification that an emergency access administrator account exists outside all Conditional Access policies. Absence of a break-glass account is classified as High severity regardless of other controls in place.

**Security Defaults and Conditional Access coexistence:** Microsoft does not permit Security Defaults and Conditional Access to run simultaneously. Assessments verify that Security Defaults are disabled before CA policy deployment and that equivalent or stronger controls exist in the CA policy set.

**SigninLogs table naming:** The Log Analytics table for interactive sign-in data is SigninLogs (lowercase i). This is a known operational detail that affects KQL query validity across all sign-in detection rules.

**P2 licensing continuity:** Risk-based Conditional Access policies and Identity Protection require active Entra ID P2 licensing. Licence expiry creates an immediate gap in CA004, CA005, and all risk-based detections. Licence renewal should be planned at least 14 days before expiry.

---

## Report Versioning

Assessment reports are versioned to reflect the cumulative state of controls at the time of issue.

| Version | Date | Scope |
|---|---|---|
| v1.2 | May 5, 2026 | Baseline hardening, Sentinel deployment, initial detection rules |
| v3.0 | May 16, 2026 | Phase 3 risk-adaptive controls, full CA framework, detection engineering stack |

---

*Secure Scale Systems Ltd | securescalesystems.com | Company No. 16405375*
