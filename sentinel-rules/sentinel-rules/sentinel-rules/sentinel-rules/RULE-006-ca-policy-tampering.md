# RULE-006: Conditional Access Policy Tampering Detection

**Rule ID:** RCC-DET-006  
**Rule Type:** Scheduled  
**Severity:** High  
**Status:** Active  

## Description

Detects modifications to Conditional Access policies including creation, update, and deletion events. CA policy tampering is a high-signal indicator of privilege abuse or attacker persistence activity. An adversary with sufficient privileges may disable or weaken CA policies to remove MFA requirements or unblock legacy authentication protocols.

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
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy"
  )
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| extend PolicyName = tostring(TargetResources[0].displayName)
| extend ModifiedProps = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, InitiatorUPN, InitiatorIP, PolicyName, Result, ModifiedProps
```

## Rule Configuration

| Parameter | Value |
|---|---|
| Query frequency | Every 1 hour |
| Query period | Last 1 hour |
| Alert threshold | Greater than 0 results |
| Alert grouping | Enabled — group by PolicyName |
| Incident creation | Enabled |

## Deployment Notes

Deployed and validated in sss-sentinel-workspace. Directly monitors the CA001-CA005 policy set. Any modification to these policies will generate an alert. Complements Content Hub rules for CA policy disabled and CA policy put into report-only mode.

## References

- [Microsoft CA Security Operations Guide](https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-infrastructure)
- MITRE ATT&CK T1556.006
