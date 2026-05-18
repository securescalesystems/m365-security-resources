# CA Policy: User Risk Block (P2)

## Overview

Blocks access for users with high user risk scores and requires a password reset before access is restored. User risk is a persistent score that accumulates over time as Identity Protection detects signals indicating an account is likely compromised, as distinct from sign-in risk which is evaluated per authentication event.

## Threat Context

An attacker who has established persistent access to a compromised account may operate quietly over an extended period, avoiding the behavioural anomalies that trigger sign-in risk scoring on any individual event. User risk accumulates this evidence over time. When credentials appear in breach databases, when suspicious activity patterns persist across multiple sessions, or when previous risk remediations fail, the user risk score reflects that ongoing threat. Blocking high-risk users and forcing a password reset breaks the attacker's access and forces credential rotation, invalidating any session tokens or stored credentials the attacker may hold.

## Policy Specification

| Field | Value |
|---|---|
| Policy Name | User Risk Block |
| Users | All users |
| Cloud Apps | All resources |
| Conditions | User risk: High |
| Grant Control | Block access, Require password change |
| Session Controls | None |
| State | Enabled |
| Licensing | Entra ID P2 |

## Exclusions

Emergency access account must be excluded.

## Operational Notes

After enabling, monitor the Risky Users blade in Identity Protection regularly. Dismiss false positives to maintain signal quality. Self-service password reset must be enabled and users must be registered for SSPR authentication methods, otherwise blocked users cannot self-remediate and will require administrator intervention to restore access.

## Dependencies

Requires Entra ID P2 licensing and Identity Protection enabled. Operates in tandem with CA004 which handles per-sign-in risk. Together they provide coverage across both real-time and persistent risk scenarios.
