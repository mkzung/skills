---
name: semgrep
description: >-
  Run Semgrep static analysis scan on a codebase using parallel subagents.
  Supports two scan modes — "run all" (full ruleset coverage) and "important
  only" (high-confidence security vulnerabilities). Automatically detects and
  uses Semgrep Pro for cross-file taint analysis when available. Use when asked
  to scan code for vulnerabilities, run a security audit with Semgrep, find
  bugs, or perform static analysis. Spawns parallel workers for multi-language
  codebases.
allowed-tools: Bash Read Glob Agent Task Workflow AskUserQuestion TaskCreate TaskList TaskUpdate
---

# Semgrep Security Scan

Run a Semgrep scan with automatic language detection, parallel execution via a dynamic workflow, and merged SARIF output.

## Essential Principles

1. **Always use `--metrics=off`** — Semgrep sends telemetry by default; `--config auto` also phones home. Every `semgrep` command must include `--metrics=off` to prevent data leakage during security audits.
2. **User must approve the scan plan (Step 3 is a hard gate)** — The original "scan this codebase" request is NOT approval. Present exact rulesets, target, engine, and mode; wait for explicit "yes"/"proceed" before spawning scanners.
3. **Third-party rulesets are required, not optional** — Trail of Bits, 0xdea, and Decurity rules catch vulnerabilities absent from the official registry. Include them whenever the detected language matches.
4. **The workflow generates the commands; do not write them yourself** — `workflows/semgrep-scan.js` builds every `semgrep` line from the approved list. That is what makes `--metrics=off`, the `--include` scoping rule, and the parallel dispatch properties of the code rather than instructions. Pass it the approved rulesets and let it run.
5. **Always check for Semgrep Pro before scanning** — Pro enables cross-file taint tracking and catches ~250% more true positives. Skipping the check means silently missing critical inter-file vulnerabilities.
6. **Report what did not run** — The workflow returns `failed` and `skipped` alongside `scans`. A ruleset whose repo would not clone, or one whose agent died, must appear in the report. A partial scan presented as a complete one is worse than no scan.

## When to Use

- Security audit of a codebase
- Finding vulnerabilities before code review
- Scanning for known bug patterns
- First-pass static analysis

## When NOT to Use

- Binary analysis → Use binary analysis tools
- Already have Semgrep CI configured → Use existing pipeline
- Need cross-file analysis but no Pro license → Consider CodeQL as alternative
- Creating custom Semgrep rules → Use `semgrep-rule-creator` skill
- Porting existing rules to other languages → Use `semgrep-rule-variant-creator` skill

## Output Directory

All scan results, SARIF files, and temporary data are stored in a single output directory.

- **If the user specifies an output directory** in their prompt, use it as `OUTPUT_DIR`.
- **If not specified**, default to `./static_analysis_semgrep_1`. If that already exists, increment to `_2`, `_3`, etc.

In both cases, **always create the directory** with `mkdir -p` before writing any files.

```bash
# Resolve output directory
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  BASE="static_analysis_semgrep"
  N=1
  while [ -e "${BASE}_${N}" ]; do
    N=$((N + 1))
  done
  OUTPUT_DIR="${BASE}_${N}"
fi
mkdir -p "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results"
```

The output directory is resolved **once** at the start of Step 1 and used throughout all subsequent steps.

```
$OUTPUT_DIR/
├── rulesets.txt                 # Approved rulesets (logged after Step 3)
├── raw/                         # Per-scan raw output (unfiltered)
│   ├── python-python.json        # <language>-<ruleset> for language-scoped rules
│   ├── python-python.sarif
│   ├── python-django.json
│   ├── python-django.sarif
│   ├── all-security-audit.json   # all-<ruleset> for cross-language rules, run once
│   ├── all-security-audit.sarif
│   └── ...
└── results/                     # Final merged output
    └── results.sarif
```

## Prerequisites

**Required:** Semgrep CLI (`semgrep --version`). If not installed, see [Semgrep installation docs](https://semgrep.dev/docs/getting-started/).

**Optional:** Semgrep Pro — enables cross-file taint tracking, inter-procedural analysis, and additional languages (Apex, C#, Elixir). Check with:

```bash
# --metrics=off because Principle 1 has no exceptions, and this is the first semgrep command
# of a run. stderr is kept because "OSS only" has several causes (logged out, no subscription,
# registry blocked) and the run downgrades silently for all of them.
if PRO_ERR=$(semgrep --pro --validate --metrics=off --config p/default 2>&1); then
  echo "Pro available"
else
  echo "OSS only"
  echo "  reason: $(printf '%s' "$PRO_ERR" | tail -n 3)"
fi
```

**Limitations:** OSS mode cannot track data flow across files. Pro mode uses `-j 1` for cross-file analysis (slower per ruleset, but parallel rulesets compensate).

## Scan Modes

Select mode in Step 2 of the workflow. Mode affects both scanner flags and post-processing.

| Mode | Coverage | Findings Reported |
|------|----------|-------------------|
| **Run all** | All rulesets, all severity levels | Everything |
| **Important only** | All rulesets, pre- and post-filtered | Security vulns only, medium-high confidence/impact |

**Important only** applies two filter layers:
1. **Pre-filter**: `--severity WARNING --severity ERROR` (CLI flag)
2. **Post-filter**: JSON metadata — keeps only `category=security`, `confidence∈{MEDIUM,HIGH}`, `impact∈{MEDIUM,HIGH}`

See [scan-modes.md](references/scan-modes.md) for metadata criteria and jq filter commands.

## Orchestration Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ MAIN SESSION (this skill)                                        │
│ Step 1: Detect languages + check Pro availability                │
│ Step 2: Select scan mode + rulesets (ref: rulesets.md)           │
│ Step 3: Present plan + rulesets, get approval [⛔ HARD GATE]     │
│ Step 4: Call Workflow with the approved rulesets                 │
│ Step 5: Post-filter, merge, report, delete repos/                │
└──────────────────────────────────────────────────────────────────┘
         │ Step 4: workflows/semgrep-scan.js
         ▼
┌──────────────────────────────────────────────────────────────────┐
│ Phase: Clone   one agent, each third-party repo once             │
│ Phase: Scan    one agent per language, plus one shared unit      │
│                ├── python     p/python, p/django                 │
│                ├── javascript p/javascript                       │
│                ├── docker     p/dockerfile                       │
│                └── cross-language  p/security-audit, p/secrets,  │
│                                    the cloned repos              │
└──────────────────────────────────────────────────────────────────┘
```

The approval gate stays in the session because workflow agents run in the background and
cannot ask the user anything. The approved list crosses into the workflow as data, so the
scan cannot reach a ruleset the user declined.

Cross-language rulesets go in one shared unit rather than being repeated per language.
`p/security-audit`, `p/secrets`, and the third-party repos scan the whole target unscoped,
so running them once per language ran the identical command N times and left the SARIF
merge to dedup the copies.

## Workflow

**Follow the detailed workflow in [scan-workflow.md](workflows/scan-workflow.md).** Summary:

| Step | Action | Gate | Key Reference |
|------|--------|------|---------------|
| 1 | Resolve output dir, detect languages + Pro availability | — | Use Glob, not Bash |
| 2 | Select scan mode + rulesets | — | [rulesets.md](references/rulesets.md) |
| 3 | Present plan, get explicit approval | ⛔ HARD | AskUserQuestion |
| 4 | Run the scan workflow | — | `workflows/semgrep-scan.js` |
| 5 | Post-filter, merge, report, clean up | — | Merge script (below) |

**Task enforcement:** On invocation, create 5 tasks with blockedBy dependencies (each step blocks the previous). Step 3 is a HARD GATE — mark complete ONLY after user explicitly approves.

**Merge command (Step 5):**

```bash
uv run {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif"
```

## Workflow and agents

| Component | Purpose |
|-----------|---------|
| [workflows/semgrep-scan.js](workflows/semgrep-scan.js) | Builds every scan command from the approved rulesets and runs them in parallel |
| `static-analysis:semgrep-scanner` | The agent the workflow spawns per unit. Runs the commands it is given; composes none of them |

The workflow passes `agentType: 'static-analysis:semgrep-scanner'` itself. Spawn that agent
directly only on the fallback path, when the `Workflow` tool is unavailable.

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "User asked for scan, that's approval" | Original request ≠ plan approval. Present plan, use AskUserQuestion, await explicit "yes" |
| "Step 3 task is blocking, just mark complete" | Lying about task status defeats enforcement. Only mark complete after real approval |
| "I already know what they want" | Assumptions cause scanning wrong directories/rulesets. Present plan for verification |
| "Just use default rulesets" | User must see and approve exact rulesets before scan |
| "Add extra rulesets without asking" | Modifying approved list without consent breaks trust |
| "Third-party rulesets are optional" | Trail of Bits, 0xdea, Decurity catch vulnerabilities not in official registry — REQUIRED |
| "Use --config auto" | Sends metrics; less control over rulesets |
| "I'll just run the semgrep commands myself" | The workflow is what enforces `--metrics=off` and the `--include` rule. Hand-written commands drop them silently |
| "The workflow reported some failures, the scan still finished" | `failed` and `skipped` are part of the result. Report them or the user reads a partial scan as a clean one |
| "The workflow said the scans succeeded, so they did" | `scans` is the agent's own report. Check each entry's own `json` and `sarif` path with `test -s` before you believe it. Do not compare counts: a scan that lied about succeeding and a `failed` scan that crashed after writing cancel out to the healthy total |
| "Pro is too slow, skip --pro" | Cross-file analysis catches 250% more true positives; worth the time |
| "Semgrep handles GitHub URLs natively" | URL handling fails on repos with non-standard YAML; always clone first |
| "Cleanup is optional" | Cloned repos pollute the user's workspace and accumulate across runs |
| "Use `.` or relative path as target" | Subagents need absolute paths to avoid ambiguity |
| "Let the user pick an output dir later" | Output directory must be resolved at Step 1, before any files are created |

## Reference Index

| File | Content |
|------|---------|
| [rulesets.md](references/rulesets.md) | Complete ruleset catalog and selection algorithm |
| [scan-modes.md](references/scan-modes.md) | Pre/post-filter criteria and jq commands |
| [scanner-task-prompt.md](references/scanner-task-prompt.md) | Scanner prompt template, used only on the fallback path |

| Workflow | Purpose |
|----------|---------|
| [scan-workflow.md](workflows/scan-workflow.md) | Complete 5-step scan execution process |
| [workflows/semgrep-scan.js](workflows/semgrep-scan.js) | The dynamic workflow Step 4 runs |

## Success Criteria

- [ ] Output directory resolved (user-specified or auto-incremented default)
- [ ] All generated files stored inside `$OUTPUT_DIR`
- [ ] Languages detected with file counts; Pro status checked
- [ ] Scan mode selected by user (run all / important only)
- [ ] Rulesets include third-party rules for all detected languages
- [ ] User explicitly approved the scan plan (Step 3 gate passed)
- [ ] Scan workflow ran and returned a result object
- [ ] `failed` and `skipped` from the workflow are empty, or listed in the report
- [ ] Every `scans` entry confirmed on disk by its own `json` and `sarif` path, not by file count
- [ ] Every `semgrep` command used `--metrics=off`
- [ ] Approved rulesets logged to `$OUTPUT_DIR/rulesets.txt`
- [ ] Raw per-scan outputs stored in `$OUTPUT_DIR/raw/`
- [ ] `results.sarif` exists in `$OUTPUT_DIR/results/` and is valid JSON
- [ ] Important-only mode: post-filter applied before merge; unfiltered results preserved in `raw/`
- [ ] Results summary reported with severity and category breakdown
- [ ] Cloned repos (if any) cleaned up from `$OUTPUT_DIR/repos/`
