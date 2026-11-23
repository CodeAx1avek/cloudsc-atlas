# CloudSec Atlas — content authoring guide

You are writing topics for a cloud security learning site that takes a reader from
"what is this" to "I can find and exploit this in a real account" across AWS, Azure
and GCP.

## The reader

A security consultant or engineer who already knows web and app security. They are
not new to security — they are new to *cloud* security, or they are a traditional
pentester who needs to get fluent in cloud quickly. They are comfortable with
`curl`, a terminal, reading a JSON policy document, and thinking about trust
boundaries.

Write for that reader. Do not explain what HTTP is. Do explain why a role trust
policy is not an IAM policy.

## The four beats, always in this order

Every topic has exactly four beats. The order is the teaching model and it is not
negotiable.

1. **Concept** — what the thing is, how it fits into the platform, why it exists.
   Give the reader a mental model they can reuse. This is the longest beat.
2. **Attack** — how it gets abused in practice. Concrete techniques with real
   commands, and the blast radius of each.
3. **Detect** — what the signal looks like in the cloud's audit logs, with a
   runnable query, plus the guardrail that limits it.
4. **Fix** — what to change, ordered by priority, with config where the config is
   short enough to show.

A topic that cannot fill all four beats is not finished.

## Voice

- Plain and direct. Short sentences. No filler, no marketing tone.
- Name things the way the platform names them. Say `sts:AssumeRole`, say
  `Microsoft Entra ID`, say `gcloud iam service-accounts`. Not "AWS STS service".
- Explain the *why* of a command, not just the command.
- Use concrete numbers where they exist: "1,365 reports", "session lasts 900
  seconds", "CVSS 9.8".
- Never pad. If a beat can be three sentences, it is three sentences.
- Do not use emoji. Do not use exclamation marks.
- Avoid the phrase "in today's cloud landscape". Avoid "leverage". Avoid "delve".

## Depth standard

A topic should read like a good internal training note: 900 to 1,600 words of
body text across the four beats. Enough that an expert reader learns something
they did not already know, not so much that they skim.

Every technique should have a **real command** that runs. Verify the syntax is
correct for the current CLI. If you are not confident a flag exists, use the
simplest form that definitely works.

Every signal should have a **real query**. Prefer CloudWatch Logs Insights
syntax for AWS (`fields ... | filter ... | stats ...`), Azure KQL for Azure
(`AzureDiagnostics | where ...`), and Google Cloud Logging for GCP
(`resource.type="..." | ...`). If you cannot write a confident query, write the
signal in prose and say which log to look in — do not invent a query.

**Be accurate.** Only cite a CVE, a real public report, or a named technique
(`iam:PassRole`, `OIDC federation`, `IMDSv1`) if you are confident it exists and
is correctly described. Prefer describing the vulnerability *class* over asserting
a specific unverified CVE number. Never fabricate a CVE ID.

## File format

Each topic is one TypeScript file in `src/data/topics/`. Look at
`src/data/topics/aws-iam-privilege-escalation.ts` — it is the exemplar and you
should match its density, structure and tone closely.

File naming: `<cloud>-<topic-slug>.ts`, lowercase and hyphenated. The `slug`
field inside is `cloud/track/topic-slug` and must match the filename.

Each file exports:

```ts
import type { Topic } from '@/types'
export const topic: Topic = { /* ... */ }
```

The `Topic` interface is in `src/types.ts`. Read it before writing. Every field
is required except the ones marked optional there.

## The topic list you are given

You will be given a specific list of topics with slug, stage, track and title.
Write one file per topic, in the given order.

## Hard rules

- Do not modify `src/types.ts`, the exemplar, or any other file. Only create your
  own topic files.
- TypeScript must compile with `noUnusedLocals` and strict mode on.
- Command strings: use `\n` inside a normal single-quoted string for line
  continuations, and escape any single quote as `\'`. Backticks inside a normal
  string are fine; inside a template literal they must be escaped as \` .
- Prefer single-quoted strings for command fields so backticks are safe.
- Each topic must have at least 2 techniques, at least 3 signals, at least 3
  remediations with at least one `critical` or `high`, and at least 4 checklist
  items.
