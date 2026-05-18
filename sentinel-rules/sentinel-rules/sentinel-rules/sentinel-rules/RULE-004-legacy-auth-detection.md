# RULE-004: Legacy Authentication Detection

## Overview

Scheduled detection rule targeting sign-ins using legacy authentication protocols. Legacy authentication cannot enforce modern MFA controls and represents a consistent attack vector for credential-based attacks. This rule provides visibility and alerting to complement the Conditional Access block on legacy authentication.

## Rule Specification

| Field | Value |
|---|---|
| Rule ID | RULE-004 |
| Rule Type | Scheduled Query Rule |
| Data Source | SigninLogs |
| Severity | Medium |
| MITRE Tactic | Initial Access, Defense Evasion |
| MITRE Technique | T1078 - Valid Accounts |
| Run Frequency | Every 5 minutes |
| Lookback Period | 1 hour |
| Alert Threshold | Greater than 0 |
| Incident Creation | Enabled |
| Alert Grouping | Enabled, 5 hours, all entities match |

## KQL Query

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ClientAppUsed in (
    "Exchange ActiveSync",
    "IMAP4",
    "MAPI Over HTTP",
    "POP3",
    "SMTP Auth",
    "Other clients"
)
| project TimeGenerated, UserPrincipalName, AppDisplayName,
    ClientAppUsed, Location, ResultType, ResultDescription,
    ConditionalAccessStatus
| order by TimeGenerated desc
```

Table name is SigninLogs (lowercase i).

## Tuning Notes

Where the CA block legacy authentication policy is correctly deployed, results should show ConditionalAccessStatus as failure. Any successful legacy authentication sign-in alongside an active CA block warrants immediate investigation as it may indicate a policy exclusion is being abused or the CA policy has a coverage gap.

## Relationship to Conditional Access

The CA policy blocks the access. This rule surfaces the attempt so the source client can be identified, updated, or decommissioned. High volumes of legacy auth attempts from a single user or application indicate a client that has not been migrated to modern authentication.
