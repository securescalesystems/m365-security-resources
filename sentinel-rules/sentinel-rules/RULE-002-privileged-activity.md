# RULE-002: Privileged Account Activity Detection

## Overview

Scheduled detection rule targeting role assignments, administrative operations, and service principal activity in Entra ID. Covers both human-initiated privileged actions and automated deployment sequences across the AuditLogs table.

## Rule Specification

| Field | Value |
|---|---|
| Rule ID | RULE-002 |
| Rule Type | Scheduled Query Rule |
| Data Source | AuditLogs |
| Severity | High |
| MITRE Tactic | Privilege Escalation |
| MITRE Technique | T1078 - Valid Accounts |
| Run Frequency | Every 5 minutes |
| Lookback Period | 1 hour |
| Alert Threshold | Greater than 0 |
| Incident Creation | Enabled |
| Alert Grouping | Enabled, 5 hours, all entities match |

## KQL Query

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where Category == "RoleManagement"
    or OperationName contains "role"
    or OperationName contains "service principal"
| project TimeGenerated, OperationName, InitiatedBy,
    TargetResources, Result
| order by TimeGenerated desc
```

## Tuning Notes

ARM-initiated and Microsoft Azure AD Internal JIT provisioning entries are expected in environments with active deployments or PIM configurations. Baseline your environment over 7 days before enforcing alert thresholds. Filter on InitiatedBy to separate human-initiated activity from automated processes.

## False Positive Considerations

PIM activations, ARM deployments, and service principal provisioning will generate results. The signal to investigate is human-initiated role assignments outside approved change windows, unexpected service principal creation, or role assignments to accounts not in your privileged access baseline.

## Enhancement Opportunity

Enable RoleManagementLogs in Entra ID diagnostic settings for granular PIM activation visibility. Join results against a Sentinel Watchlist of authorised administrators for automated triage and noise reduction.
