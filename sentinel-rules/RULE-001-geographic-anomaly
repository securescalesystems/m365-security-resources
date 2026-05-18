# RULE-001: Geographic Anomaly Detection

## Overview

Scheduled detection rule targeting authentication events originating outside the organisation's confirmed operating geography. Designed for single or limited-geography tenants where out-of-country sign-ins have a high probability of indicating account compromise or credential theft.

## Rule Specification

| Field | Value |
|---|---|
| Rule ID | RULE-001 |
| Rule Type | Scheduled Query Rule |
| Data Source | AADNonInteractiveUserSignInLogs |
| Severity | High |
| MITRE Tactic | Initial Access |
| MITRE Technique | T1078 - Valid Accounts |
| Run Frequency | Every 1 hour |
| Lookback Period | 1 hour |
| Alert Threshold | Greater than 0 |
| Incident Creation | Enabled |
| Alert Grouping | Enabled, 5 hours, all entities match |

## KQL Query

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1h)
| where Location != "NG"
| project TimeGenerated, UserPrincipalName, AppDisplayName,
    IPAddress, Location, ResultType, ResultDescription
```

Update the Location filter to your operating country code (ISO 3166-1 alpha-2). For multi-geography tenants use `Location !in ("NG", "GB")` syntax.

## Tuning Notes

This rule is intentionally broad. Tune the exclusion list to account for known VPN exit nodes, legitimate travel patterns, and service account activity from cloud infrastructure. Consider adding a Named Location exclusion in Conditional Access alongside this rule for automated response coverage.

## False Positive Considerations

Cloud service infrastructure, CDN nodes, and Microsoft-operated services may surface in non-interactive sign-in logs with unexpected geographies. Review the AppDisplayName field to triage automated service activity against human sign-ins before escalating.
