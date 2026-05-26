# RULE-007: MFA Authentication Method Changes Detection

**Rule ID:** RCC-DET-007  
**Rule Type:** Scheduled  
**Severity:** High  
**Status:** Active  

## Description

Detects modifications to MFA and authentication methods including disabling strong authentication, deleting registered authentication methods, and updating MFA settings. An adversary who has compromised a privileged account may attempt to disable or modify MFA to maintain persistent access without triggering MFA prompts on subsequent logins.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Defense Evasion |
| Technique | T1556 - Modify Authentication Process |
| Sub-technique | T1556.006 - Multi-Factor Authentication |

## Data Sources

| Source | Table | Connector |
|---|---|---|
| Microsoft Entra ID | AuditLogs | Microsoft Entra ID Diagnostic Settings |

## KQL Query

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in (
    "Update user",
    "Update Authentication Methods",
    "Delete Authentication Method",
    "Disable Strong Authentication",
    "Update StsRefreshTokenValidFrom",
    "Update MFA"
  )
    or (OperationName == "Update user" and TargetResources has "StrongAuthenticationRequirement")
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend ModifiedProps = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, InitiatorUPN, InitiatorIP, TargetUPN, Result, ModifiedProps
```

## Rule Configuration

| Parameter | Value |
|---|---|
| Query frequency | Every 1 hour |
| Query period | Last 1 hour |
| Alert threshold | Greater than 0 results |
| Alert grouping | Enabled — group by TargetUPN |
| Incident creation | Enabled |

## Deployment Notes

Deployed and validated in sss-sentinel-workspace. Targets authentication method modification events in AuditLogs. High-fidelity rule — MFA method changes on production accounts are rare and warrant immediate investigation.

## References

- [Microsoft Authentication Methods Security Operations](https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts)
- MITRE ATT&CK T1556.006
