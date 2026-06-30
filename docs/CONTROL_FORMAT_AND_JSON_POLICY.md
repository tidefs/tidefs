# Control Format And JSON Policy

Maturity: current policy guardrail.

This document records the current TideFS boundary for operator-visible output,
control-plane payloads, durable recovery records, and evidence artifacts. It
does not implement a new format, widen release claims, or freeze a production
ABI.

## Core Rule

Ordinary TideFS operator surfaces must be human-oriented by default. Status,
refusal, and tuning commands should render structured text with source and
freshness context instead of requiring operators to read, edit, or paste JSON.

Runtime control paths, hot paths, wire protocols, on-disk formats, and durable
recovery records must use explicit typed records and versioned codecs selected
by current source authority and issue scope. JSON, BSON, YAML, and similar
document blobs are not acceptable default product carriers for those paths.

## Allowed JSON Uses

JSON remains acceptable for narrow non-product or explicitly machine-oriented
surfaces:

- CI, validation, evidence, trace, replay, and support-bundle artifacts;
- debug, forensic, and diagnostic exports that are source-qualified;
- explicit expert or automation output such as a documented `--json` flag;
- temporary pre-alpha scaffolding when a current issue names the owner, scope,
  validation, and removal or graduation condition.

These uses must not silently become the ordinary operator UX, a final control
protocol, or durable pool/storage authority.

## Transitional Debt

Current pre-alpha source still contains JSON in some live-admin and local
record paths, including live-owner request payloads and matching local parser
code, plus device-removal and rebuild record helpers. Those uses are
transitional development debt, not product format authority. Work touching
those paths should either move them toward typed/versioned formats or record a
focused follow-up issue explaining why the current slice cannot.

Replacing JSON with BSON or another document blob is not a product fix. The
desired direction is typed command/result records, fixed or length-delimited
binary codecs where performance or durability matters, and human-oriented
default rendering for operator commands.

## Review Checklist

Before adding a new JSON-bearing path, answer all of these:

1. Is this evidence/debug/export rather than ordinary operator UX?
2. Is it outside a hot path, wire protocol, on-disk format, and durable
   recovery path?
3. If operators see it, is JSON behind an explicit expert or machine-output
   option?
4. If the path is transitional, which issue owns its removal or graduation?
5. What typed/versioned authority would replace it for production use?

## Non-Claims

This policy does not prove that current TideFS control, durable, or operator
surfaces already satisfy the boundary. It classifies the direction and review
bar for future work while TideFS remains pre-alpha.
