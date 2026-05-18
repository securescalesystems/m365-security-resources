# CA Policy: Require MFA for Administrators

## Overview

Enforces multi-factor authentication for all users holding privileged directory roles. Admin accounts are the highest-value targets in any Microsoft 365 environment. A single compromised Global Administrator account gives an attacker full tenant control including the ability to disable all other security controls.

## Threat Context

Privileged accounts are disproportionately targeted in credential-based attacks. Once an attacker obtains admin credentials through phishing, credential stuffing, or password spray, they can create backdoor accounts, disable MFA for all users, exfiltrate data, and establish persistent access. Enforcing MFA on all privileged roles ensures that credential theft alone is insufficient for admin-level compromise. This policy exists independently of CA003 so that admin MFA enforcement survives any modification to the broader user MFA policy.

## Policy Specification

| Field | Value |
|---|---|
| Policy Name | Require MFA for Admins |
| Users | Directory roles |
| Target Roles | Global Administrator, Security Administrator, Conditional Access Administrator, Exchange Administrator, SharePoint Administrator, User Administrator, Privileged Role Administrator, Privileged Authentication Administrator |
| Cloud Apps | All resources |
| Conditions | None |
| Grant Control | Require multifactor authentication |
| Session Controls | None |
| State | Enabled |
| Licensing | Entra ID P1 |

## Exclusions

Emergency access account must be excluded. The break-glass account provides recovery access in the event of MFA infrastructure failure and must remain outside all CA policies by design.

## Validation

Sign in as a directory role holder. An MFA challenge should trigger before access is granted. Navigate to Sign-in logs, Conditional Access tab on the sign-in event, and confirm the policy shows as Success.
