# RULE-005: PIM Privilege Escalation Detection

**Rule ID:** RCC-DET-005  
**Rule Type:** Scheduled  
**Severity:** High  
**Status:** Active  

## Description

Detects privilege escalation via Privileged Identity Management (PIM) role activation. Monitors for users activating high-value directory roles including Global Administrator, Security Administrator, and Privileged Role Administrator. Elevated role activations outside of expected patterns may indicate compromised accounts or insider threat activity.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Privilege Escalation |
| Technique | T1078 - Valid Accounts |
| Sub-technique | T1078.004 - Cloud Accounts |

## Data Sources

| Source | Table | Connector |
|---|---|---|
| Microsoft Entra ID | AuditLogs | Microsoft Entra ID Diagnostic Settings |

## KQL Query

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in (
    "Add member to role completed (PIM activation)",
    "Add eligible member to role",
    "Add member to role outside PIM"
  )
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetRole = tostring(TargetResources[0].displayName)
| extend ActivatedBy = tostring(TargetResources[1].userPrincipalName)
| where TargetRole in (
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator"
  )
| project TimeGenerated, OperationName, InitiatorUPN, InitiatorIP, TargetRole, ActivatedBy, Result
```

## Rule Configuration

| Parameter | Value |
|---|---|
| Query frequency | Every 1 hour |
| Query period | Last 1 hour |
| Alert threshold | Greater than 0 results |
| Alert grouping | Enabled — group by InitiatorUPN |
| Incident creation | Enabled |

## Deployment Notes

Deployed and validated in sss-sentinel-workspace. Rule fires on PIM activation events sourced from AuditLogs. Complements Content Hub rule NRT PIM Elevation Request Rejected which covers rejected activations.

## References

- [Microsoft PIM Security Operations Guide](https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-identity-management)
- MITRE ATT&CK T1078.004
