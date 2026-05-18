# CA Policy: Sign-in Risk MFA Step-up (P2)

## Overview

Requires additional MFA verification in real-time when Entra Identity Protection scores a sign-in as medium or high risk. Operates as an adaptive control that escalates authentication requirements based on live threat signals rather than applying blanket friction to all sign-ins.

## Threat Context

Not all sign-ins carry equal risk. An attacker using a stolen credential from an anonymising proxy, an unfamiliar device, or a geography inconsistent with the user's pattern presents a materially different threat than a routine sign-in from a known device and location. Static MFA policies treat both identically. Risk-based step-up authentication applies additional verification precisely when the signal warrants it, challenging the attacker while preserving a frictionless experience for legitimate users signing in under normal conditions. This policy requires P2 because it depends on Identity Protection's real-time risk scoring engine.

## Policy Specification

| Field | Value |
|---|---|
| Policy Name | Sign-in Risk MFA Step-up |
| Users | All users |
| Cloud Apps | All resources |
| Conditions | Sign-in risk: Medium, High |
| Grant Control | Require multifactor authentication |
| Session Controls | None |
| State | Enabled |
| Licensing | Entra ID P2 |

## Risk Signals That Trigger This Policy

Atypical travel, anonymous IP address, malware-linked IP, unfamiliar sign-in properties, leaked credentials, and password spray attack patterns as scored by Microsoft's global threat intelligence.

## Exclusions

Emergency access account must be excluded.

## Dependencies

Requires Entra ID P2 licensing and Identity Protection enabled. Pair with CA005 for high user risk scenarios and RULE-003 (NRT detection rule) for SOC visibility alongside automated response.
