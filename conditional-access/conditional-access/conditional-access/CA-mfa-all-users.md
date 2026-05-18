# CA Policy: Require MFA for All Users

## Overview

Enforces multi-factor authentication across all users for all cloud application access. This is the foundational Zero Trust identity control, ensuring that stolen credentials alone are insufficient for account compromise regardless of the target account's privilege level.

## Threat Context

The majority of account compromise incidents in Microsoft 365 environments involve valid credentials obtained through phishing, credential stuffing, or data breach exposure. Without MFA, a valid username and password is all an attacker needs. Enforcing MFA tenant-wide raises the cost of every credential-based attack from trivial to requiring physical access to the victim's registered authentication device. Combined with CA004 and CA005, this policy forms a layered identity defence that covers both standard and risk-elevated sign-in scenarios.

## Policy Specification

| Field | Value |
|---|---|
| Policy Name | Require MFA for All Users |
| Users | All users |
| Cloud Apps | All resources |
| Conditions | None |
| Grant Control | Require multifactor authentication |
| Session Controls | None |
| State | Enabled |
| Licensing | Entra ID P1 |

## Prerequisites

Security Defaults must be disabled before enabling this policy. Microsoft does not permit Security Defaults and Conditional Access to run simultaneously. Ensure the emergency access account is configured before disabling Security Defaults. Verify all users have completed MFA registration before enabling, as unregistered users will be blocked on first sign-in.

## Exclusions

Emergency access account must be excluded. This account exists specifically to recover tenant access in the event of MFA infrastructure failure and must remain outside all CA policies by design.

## Validation

Sign in as a standard user account. MFA challenge should trigger. Navigate to Sign-in logs, Conditional Access tab, and confirm policy shows as Success. Not Applied status on your admin account is expected if the emergency access exclusion is correctly configured.
