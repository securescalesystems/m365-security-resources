# RULE-003: Risky Sign-in Detection (Near Real-Time)

## Overview

Near Real-Time detection rule targeting medium and high risk sign-ins scored by Microsoft Entra Identity Protection. NRT rule type selected deliberately over Scheduled to minimise detection latency on high-confidence identity risk signals. Fires within approximately one minute of a matching event.

## Rule Specification

| Field | Value |
|---|---|
| Rule ID | RULE-003 |
| Rule Type | Near Real-Time (NRT) |
| Data Source | SigninLogs |
| Severity | High |
| MITRE Tactic | Initial Access |
| MITRE Technique | T1078 - Valid Accounts |
| Run Frequency | Approximately every 1 minute |
| Alert Threshold | Greater than 0 |
| Incident Creation | Enabled |
| Alert Grouping | Enabled, 5 hours, all entities match |
| Licensing | Entra ID P2 |

## KQL Query

```kql
SigninLogs
| where RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, AppDisplayName,
    RiskLevelDuringSignIn, RiskDetail, RiskState,
    Location, ResultType, ConditionalAccessStatus
```

NRT rules do not use a TimeGenerated filter. The engine manages the time window automatically. Table name is SigninLogs (lowercase i).

## Tuning Notes

This rule operates on Identity Protection risk scores, not raw behavioural signals. Risk scoring is handled upstream by Microsoft's global threat intelligence. Tune response severity based on your organisation's risk tolerance for medium vs high risk events. Consider splitting into two rules if different response playbooks apply to each risk level.

## Dependencies

Requires Entra ID P2 licensing, Identity Protection enabled, and SigninLogs streaming to the Sentinel workspace via Entra ID diagnostic settings. Pair with Conditional Access policies CA004 (sign-in risk MFA step-up) and CA005 (user risk block) for automated response alongside this detection alert.
