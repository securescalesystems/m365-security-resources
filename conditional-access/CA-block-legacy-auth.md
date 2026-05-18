# CA Policy: Block Legacy Authentication

## Overview

Blocks all authentication attempts using legacy protocols that cannot enforce modern MFA controls. Legacy authentication bypasses Conditional Access entirely if not explicitly blocked, making this policy a foundational Zero Trust control.

## Threat Context

Legacy authentication protocols were designed before MFA existed. An attacker with valid credentials can authenticate directly via IMAP or SMTP Auth, completely bypassing any MFA controls or Conditional Access policies that do not explicitly target these protocols. Password spray attacks almost exclusively target legacy authentication endpoints because of this bypass. Blocking legacy authentication removes an entire class of credential-based attack from the threat surface.

## Policy Specification

| Field | Value |
|---|---|
| Policy Name | Block Legacy Authentication |
| Users | All users |
| Cloud Apps | All resources |
| Conditions | Client apps: Exchange ActiveSync, Other clients |
| Grant Control | Block access |
| Session Controls | None |
| State | Enabled |
| Licensing | Entra ID P1 |

## Protocols Blocked

Exchange ActiveSync, IMAP4, POP3, SMTP Auth, MAPI over HTTP, and other legacy authentication clients. Modern authentication clients including current Outlook versions, Microsoft 365 apps, Teams, and browser-based access are not affected.

## Exclusions

Emergency access account must be excluded. Standard exclusion pattern applies across all CA policies.

## Validation

After deployment, filter Sign-in logs by Client app. Legacy authentication attempts will show ConditionalAccessStatus as failure. Successful legacy authentication sign-ins alongside an active block indicate a policy gap requiring investigation.

## Relationship to RULE-004

This policy blocks legacy authentication at the access layer. RULE-004 (Legacy Authentication Detection) provides SOC visibility into attempts so source clients can be identified and migrated to modern authentication.
