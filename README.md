# AWS connect — stack + OIDC

How a customer grants Monolayer access to their AWS account. Same model as the old Hub, now with
**`app.monolayer.io`** as the OIDC provider. **No long-lived AWS keys are ever stored.**

## Files
| File | What |
|------|------|
| `monolayer-app-role-v1.yaml` | CloudFormation the customer runs. Creates the IAM **OIDC provider** (trusting `app.monolayer.io/monolayer-oidc`), the **Monolayer-App-Role** (assumed by the app via OIDC, pinned to the customer's `sub`), the **operator/build/exec IAM roles**, and an auto-callback Lambda. |

## How it works
```
1. Dashboard builds a "Launch Stack" URL: the S3 template + prefilled CustomerId + CallbackUrl.
2. Customer runs the stack in their AWS account →
     - creates IAM OIDC provider trusting https://app.monolayer.io/monolayer-oidc
     - creates Monolayer-App-Role (trust: sub == CustomerId, aud == sts.amazonaws.com)
     - creates Monolayer-Operator-TaskRole / -EcsTaskExecutionRole / -Build-InstanceRole
     - callback Lambda POSTs the role ARNs to CallbackUrl (app backend) → account auto-linked
3. app mints a short-lived OIDC JWT (sub = CustomerId) and calls
     sts:AssumeRoleWithWebIdentity(Monolayer-App-Role) → temp creds → PROVISIONS the operator.
4. The operator then runs as Monolayer-Operator-TaskRole and does builds/deploys in-account.
```

## Control-plane requirements (so AWS trusts us)
The app must publicly serve (via `app.monolayer.io`, routed by the frontend nginx `/monolayer-oidc/`):
- `https://app.monolayer.io/monolayer-oidc/.well-known/openid-configuration`
- `https://app.monolayer.io/monolayer-oidc/.well-known/jwks.json`

Set on `app-cloud` (the OIDC provider + sole key holder):
- `OIDC_ISSUER_URL=https://app.monolayer.io/monolayer-oidc`
- `OIDC_KEY_ID=monolayer-oidc-1`
- `OIDC_PRIVATE_KEY=<PEM>`  → `openssl genrsa 2048` (the public half is published in the JWKS)

## Roles the stack creates
| Role | Assumed by | Purpose |
|------|-----------|---------|
| `Monolayer-App-Role` | the app (OIDC web-identity) | provision + manage the operator (ECS/EC2/ECR/ELB/Logs + PassRole) |
| `Monolayer-Operator-TaskRole` | ECS tasks (the operator) | runtime build + deploy (EC2 start/stop, SSM, ECR, ECS, ALB, secrets) |
| `Monolayer-Operator-EcsTaskExecutionRole` | ECS tasks | image pull + container logs |
| `Monolayer-Build-InstanceRole` | EC2 (build box) | ECR push, read build secrets, SSM-managed (job delivery) |

## Publishing
Published to (same bucket as the old platform):
```
https://monolayer-hub-discovery.s3.us-east-1.amazonaws.com/monolayer-app-role-v1.yaml
```
The backend builds the Launch-Stack URL from this (`CFN_TEMPLATE_URL`, served by
`GET /api/v1/aws/connect-url`). On each template change, bump the filename version
(`-v2.yaml`, …), re-upload, and update `CFN_TEMPLATE_URL`.

