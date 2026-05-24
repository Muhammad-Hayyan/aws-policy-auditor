# AWS Policy Auditor

Paste an AWS IAM policy JSON. Get back a plain English risk report — no cloud knowledge required.

Built for compliance auditors who need to understand what a policy does, not read it.

---

## What it produces

- A HIGH / MEDIUM / LOW risk rating with a one-line summary
- Every permission translated into plain business language, grouped by severity
- A formal audit findings checklist (Finding / Pass)
- 2–4 pre-written questions to send to your cloud team

No AWS action names, no JSON, no jargon in the output.

---

## How scoring works

Start at 100. Deductions:

- Wildcard action (`*`) — 40 points
- Each critical permission found — 10 points each (max 40)
- Wildcard resource — 20 points
- No condition blocks — 10 points
- Audit log tampering actions present — 15 points
- `iam:CreateAccessKey` present — 10 points

Additions: condition blocks (+10), explicit deny statements (+10), scoped resources (+5).

Score 0–40 = HIGH risk. 41–70 = MEDIUM. 71–100 = LOW.

---

## Permission database

Actions not in the curated dictionary are resolved against a local database of 20,873 AWS permissions. The database (`public/iam_definition.json`) is derived from [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset), a community scrape of the AWS Service Authorization Reference. Credit to [@iann0036](https://github.com/iann0036) for maintaining it.

Risk tier mapping from the dataset: `Permissions management` = Critical, `Write` = Medium, `Read / List / Tagging` = Low.

---

## Stack

React, Vite, TypeScript, Tailwind CSS v4, shadcn/ui.

Entirely client-side — no backend, no API calls, no authentication. The permissions database is fetched once on page load and cached in memory.

Core analysis logic: `src/lib/policyAnalyzer.ts`

---

## Running locally

```bash
npm install
npm run dev
```

```bash
npm run build      # production build
npm run typecheck  # type check only
```

---

## License

MIT
