# Microsoft 365 Security Operations
### Detection Engineering and Identity Security Resources

**Secure Scale Systems Ltd** | Cloud Security Consultancy | United Kingdom  
[securescalesystems.com](https://securescalesystems.com)

---

## About This Repository

This repository contains production-ready security templates, KQL detection queries, Conditional Access policy specifications, and Microsoft Sentinel analytics rule configurations for organisations running Microsoft 365 and Microsoft Entra ID.

Every resource in this repository has been deployed and validated in a live Microsoft 365 environment. These are not theoretical controls — they are operational security configurations tested against real sign-in telemetry and identity data.

Organisations can use these resources to:

- Assess their current Microsoft 365 security posture
- Deploy structured Conditional Access policies aligned to Zero Trust principles
- Build a KQL threat hunting query library in Microsoft Sentinel
- Stand up detection rules covering the most common M365 identity attack patterns

---

## What Is Included

### Conditional Access Policy Templates

Five policy templates covering the core Microsoft Zero Trust identity baseline:

| Policy | Purpose | Licensing Requirement |
|---|---|---|
| Block Legacy Authentication | Prevent authentication via legacy protocols (IMAP, POP3, SMTP Auth, Exchange ActiveSync) | Entra ID P1 |
| Require MFA for Administrators | Enforce MFA on all privileged directory roles | Entra ID P1 |
| Require MFA for All Users | Enforce MFA across all users and cloud applications | Entra ID P1 |
| Sign-in Risk MFA Step-up | Require MFA when Identity Protection flags medium or high sign-in risk | Entra ID P2 |
| User Risk Block | Block access and require password reset on high-risk user accounts | Entra ID P2 |

Each template documents: policy scope, user assignments, conditions, grant controls, exclusions, and validation steps. Templates are in the [`/conditional-access`](/conditional-access) directory.

### KQL Threat Hunting Query Library

Eight KQL queries covering identity monitoring, authentication analysis, and detection engineering:

| Query | Purpose | Data Source |
|---|---|---|
| Workspace Inventory | Enumerate all populated tables in a Sentinel workspace | All tables |
| Non-Interactive Sign-In Review | Surface background authentication events from service accounts and apps | AADNonInteractiveUserSignInLogs |
| Failed Authentication Events | Identify and baseline failed sign-in attempts | SigninLogs |
| Privileged Account Activity | Detect role assignments, admin operations, and service principal activity | AuditLogs |
| Sign-In Location Baseline | Establish and monitor expected sign-in geographies | SigninLogs |
| Risky Sign-in Detection | Detect medium and high risk sign-ins flagged by Identity Protection | SigninLogs |
| MFA Fatigue Detection | Identify MFA push bombing attempts (3 or more failures within one hour) | SigninLogs |
| Conditional Access Failure Detection | Surface CA policy failures and potential bypass attempts | SigninLogs |

All queries are in the [`/kql`](/kql) directory with usage notes and expected results documented.

### Microsoft Sentinel Analytics Rules

Four scheduled and near-real-time detection rules mapped to MITRE ATT&CK:

| Rule | Type | Severity | MITRE Coverage |
|---|---|---|---|
| Geographic Anomaly Detection | Scheduled | High | T1078 - Valid Accounts |
| Privileged Account Activity | Scheduled | High | T1078 - Valid Accounts |
| Risky Sign-in Detection | Near Real-Time (NRT) | High | T1078 - Valid Accounts |
| Legacy Authentication Detection | Scheduled | Medium | T1078 - Valid Accounts, Defense Evasion |

Rule specifications, KQL queries, and deployment instructions are in the [`/sentinel-rules`](/sentinel-rules) directory.

### Security Assessment Framework

A structured M365 security assessment methodology aligned to:

- CIS Microsoft 365 Foundations Benchmark v3.1.0
- Microsoft Zero Trust Maturity Model
- NIST Cybersecurity Framework (CSF) 2.0
- Nigeria Data Protection Regulation (NDPR) 2019 and UK GDPR

Assessment documentation is in the [`/docs`](/docs) directory.

---

## Repository Structure

```
/
├── README.md
├── kql/
│   ├── detect-risky-signins.kql
│   ├── detect-mfa-fatigue.kql
│   ├── detect-ca-failures.kql
│   ├── detect-privileged-activity.kql
│   ├── detect-legacy-auth.kql
│   ├── hunt-failed-auth.kql
│   ├── hunt-location-baseline.kql
│   └── inventory-workspace-tables.kql
├── sentinel-rules/
│   ├── RULE-001-geographic-anomaly.md
│   ├── RULE-002-privileged-activity.md
│   ├── RULE-003-risky-signin-nrt.md
│   └── RULE-004-legacy-auth-detection.md
├── conditional-access/
│   ├── CA-block-legacy-auth.md
│   ├── CA-mfa-admins.md
│   ├── CA-mfa-all-users.md
│   ├── CA-signin-risk-stepup.md
│   └── CA-user-risk-block.md
└── docs/
    └── m365-security-assessment-framework.md
```

---

## Prerequisites

To deploy the resources in this repository your organisation will need:

- Microsoft 365 Business or Enterprise subscription
- Microsoft Entra ID (formerly Azure Active Directory)
- Entra ID P1 licensing minimum for Conditional Access policies
- Entra ID P2 licensing for risk-based policies (CA sign-in risk and user risk templates)
- Microsoft Sentinel deployed on a Log Analytics workspace
- Entra ID diagnostic settings configured to stream logs to the Sentinel workspace

---

## Important Notes

**Break-glass account:** Before deploying any Conditional Access policy, create an emergency administrator account that is excluded from all CA policies. Failure to do this risks permanent tenant lockout. See the Conditional Access deployment guide for full instructions.

**Security Defaults:** Conditional Access and Microsoft Security Defaults cannot run simultaneously. Disable Security Defaults before enabling CA policies. Ensure your break-glass account is in place first.

**SigninLogs table naming:** In Microsoft Sentinel Log Analytics, the interactive sign-in table is named `SigninLogs` (lowercase i). Using `SignInLogs` will return a table not found error.

**P2 licensing expiry:** Risk-based CA policies (sign-in risk and user risk) require active Entra ID P2 licensing. If P2 lapses, CA004 and CA005 equivalent policies will stop evaluating. Monitor licence expiry dates.

---

## About Secure Scale Systems Ltd

Secure Scale Systems Ltd is a UK-registered cloud security consultancy (Company No. 16405375) specialising in Microsoft 365 security engineering, Detection Engineering, and Identity Security. We help businesses of all sizes design, deploy, and operate enterprise-grade security controls on Microsoft cloud platforms.

**Services:**
- M365 and Entra ID security assessments
- Conditional Access design and deployment
- Microsoft Sentinel deployment and detection engineering
- KQL query development and threat hunting
- Security posture reviews aligned to CIS and Zero Trust frameworks

[Get in touch](https://securescalesystems.com)

---

## Standards and References

- [CIS Microsoft 365 Foundations Benchmark v3.1.0](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Zero Trust Maturity Model](https://learn.microsoft.com/security/zero-trust/)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [Microsoft Entra ID Documentation](https://learn.microsoft.com/entra/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/azure/sentinel/)
- [Microsoft Conditional Access Documentation](https://learn.microsoft.com/entra/identity/conditional-access/)

---

*Resources in this repository are updated as controls and detection techniques evolve. Contributions and issue reports are welcome.*
