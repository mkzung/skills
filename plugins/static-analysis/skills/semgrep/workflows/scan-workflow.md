# Semgrep Scan Workflow

Complete 5-step scan execution process. Read from start to finish and follow each step in order.

## Task System Enforcement

On invocation, create these tasks with dependencies:

```
TaskCreate: "Detect languages and Pro availability" (Step 1)
TaskCreate: "Select scan mode and rulesets" (Step 2) - blockedBy: Step 1
TaskCreate: "Present plan with rulesets, get approval" (Step 3) - blockedBy: Step 2
TaskCreate: "Execute scans with approved rulesets and mode" (Step 4) - blockedBy: Step 3
TaskCreate: "Merge results and report" (Step 5) - blockedBy: Step 4
```

### Mandatory Gate

| Task | Gate Type | Cannot Proceed Until |
|------|-----------|---------------------|
| Step 3 | **HARD GATE** | User explicitly approves rulesets + plan |

Mark Step 3 as `completed` ONLY after user says "yes", "proceed", "approved", or equivalent.

---

## Step 1: Resolve Output Directory, Detect Languages and Pro Availability

> **Entry:** User has specified or confirmed the target directory.
> **Exit:** `OUTPUT_DIR` resolved and created; language list with file counts produced; Pro availability determined.

### Resolve Output Directory

If the user specified an output directory in their prompt, use it as `OUTPUT_DIR`. Otherwise, auto-increment. In both cases, **always `mkdir -p`** to ensure the directory exists.

```bash
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

# Absolute from here on. Step 4 throws on a relative path, and that throw lands *after* the
# user has passed the hard gate, so a path this skill generated itself would send them back
# through approval. The workflow's "is the output directory inside the target" check also
# compares two absolute prefixes and silently does nothing on a relative pair, which is how
# a run ends up scanning its own cloned rule repos.
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
# The -d test first: `cd ""` returns 0, so a TARGET that was never bound would pass a bare
# `cd || exit` and silently resolve to the session's CWD, scanning whatever happens to be there.
[ -n "$TARGET" ] && [ -d "$TARGET" ] || { echo "ERROR: TARGET is unset or not a directory"; exit 1; }
TARGET=$(cd "$TARGET" && pwd)
echo "Output directory: $OUTPUT_DIR"
echo "Target: $TARGET"
```

Pass `$TARGET` and `$OUTPUT_DIR` to Step 4 exactly as resolved here. Do not re-derive either.

`$OUTPUT_DIR` is used by all subsequent steps. Pass its **absolute path** to scanner subagents. Scanners write raw output to `$OUTPUT_DIR/raw/`; merged/filtered results go to `$OUTPUT_DIR/results/`.

**Detect Pro availability** (requires Bash):

```bash
if ! command -v semgrep >/dev/null 2>&1; then
  echo "ERROR: semgrep is not installed. Install from https://semgrep.dev/docs/getting-started/"
  exit 1
fi
semgrep --version
# --metrics=off applies here too. This is the first semgrep invocation of the run and it
# resolves p/default against the registry, so without the flag an audit phones home before
# the user has approved anything. Principle 1 has no exceptions.
semgrep --pro --validate --metrics=off --config p/default 2>/dev/null && echo "Pro: AVAILABLE" || echo "Pro: NOT AVAILABLE"
```

**Detect languages** using Glob (not Bash). Run these patterns against the target directory and count matches:

`**/*.py`, `**/*.js`, `**/*.ts`, `**/*.tsx`, `**/*.jsx`, `**/*.go`, `**/*.rb`, `**/*.java`, `**/*.php`, `**/*.c`, `**/*.cpp`, `**/*.rs`, `**/Dockerfile`, `**/*.tf`

Also check for framework markers: `package.json`, `pyproject.toml`, `Gemfile`, `go.mod`, `Cargo.toml`, `pom.xml`. Use Read to inspect these files for framework dependencies (e.g., read `package.json` to detect React, Express, Next.js; read `pyproject.toml` for Django, Flask, FastAPI).

Map findings to categories:

| Detection | Category |
|-----------|----------|
| `.py`, `pyproject.toml` | Python |
| `.js`, `.ts`, `package.json` | JavaScript/TypeScript |
| `.go`, `go.mod` | Go |
| `.rb`, `Gemfile` | Ruby |
| `.java`, `pom.xml` | Java |
| `.php` | PHP |
| `.c`, `.cpp` | C/C++ |
| `.rs`, `Cargo.toml` | Rust |
| `Dockerfile` | Docker |
| `.tf` | Terraform |
| k8s manifests | Kubernetes |

---

## Step 2: Select Scan Mode and Rulesets

> **Entry:** Step 1 complete — languages detected, Pro status known.
> **Exit:** Scan mode selected; structured rulesets JSON compiled for all detected languages.

**First, select scan mode** using `AskUserQuestion`:

```
header: "Scan Mode"
question: "Which scan mode should be used?"
multiSelect: false
options:
  - label: "Run all (Recommended)"
    description: "Full coverage — all rulesets, all severity levels"
  - label: "Important only"
    description: "Security vulnerabilities only — medium-high confidence and impact, no code quality"
```

Record the selected mode. It affects Steps 4 and 5.

**Then, select rulesets.** Using the detected languages and frameworks from Step 1, follow the **Ruleset Selection Algorithm** in [rulesets.md](../references/rulesets.md).

The algorithm covers:
1. Security baseline (always included)
2. Language-specific rulesets
3. Framework rulesets (if detected)
4. Infrastructure rulesets
5. **Required** third-party rulesets (Trail of Bits, 0xdea, Decurity — NOT optional)
6. Registry verification

**Output:** Structured JSON passed to Step 3 for user review:

```json
{
  "baseline": ["p/security-audit", "p/secrets"],
  "python": ["p/python", "p/django"],
  "javascript": ["p/javascript", "p/react", "p/nodejs"],
  "docker": ["p/dockerfile"],
  "third_party": ["https://github.com/trailofbits/semgrep-rules"]
}
```

---

## Step 3: CRITICAL GATE — Present Plan and Get Approval

> **Entry:** Step 2 complete — scan mode and rulesets selected.
> **Exit:** User has explicitly approved the plan (quoted confirmation).

> **⛔ MANDATORY CHECKPOINT — DO NOT SKIP**
>
> This step requires explicit user approval before proceeding.
> User may modify rulesets before approving.

Present plan to user with **explicit ruleset listing**:

```
## Semgrep Scan Plan

**Target:** /path/to/codebase
**Output directory:** $OUTPUT_DIR
**Engine:** Semgrep Pro (cross-file analysis) | Semgrep OSS (single-file)
**Scan mode:** Run all | Important only (security vulns, medium-high confidence/impact)
[in important-only mode, add:] Note: important-only passes --severity WARNING --severity ERROR
to every command, including the third-party repos. Trail of Bits / 0xdea / Decurity rules that
ship with CLI severity INFO are dropped at scan time, before the metadata filter that would
otherwise keep them. Choose "Run all" if you want those.

### Detected Languages/Technologies:
- Python (1,234 files) - Django framework detected
- JavaScript (567 files) - React detected
- Dockerfile (3 files)

### Rulesets to Run:

**Security Baseline (always included):**
- [x] `p/security-audit` - Comprehensive security rules
- [x] `p/secrets` - Hardcoded credentials, API keys

**Python (1,234 files):**
- [x] `p/python` - Python security patterns
- [x] `p/django` - Django-specific vulnerabilities

**JavaScript (567 files):**
- [x] `p/javascript` - JavaScript security patterns
- [x] `p/react` - React-specific issues
- [x] `p/nodejs` - Node.js server-side patterns

**Docker (3 files):**
- [x] `p/dockerfile` - Dockerfile best practices

**Third-party (auto-included for detected languages):**
- [x] Trail of Bits rules - https://github.com/trailofbits/semgrep-rules

**Want to modify rulesets?** Tell me which to add or remove.
**Ready to scan?** Say "proceed" or "yes".
```

**⛔ STOP: Await explicit user approval.**

1. **If user wants to modify rulesets:** Add/remove as requested, re-present the updated plan, return to waiting.
2. **Use AskUserQuestion** if user hasn't responded:
   ```
   "I've prepared the scan plan with N rulesets (including Trail of Bits). Proceed with scanning?"
   Options: ["Yes, run scan", "Modify rulesets first"]
   ```
3. **Valid approval:** "yes", "proceed", "approved", "go ahead", "looks good", "run it"
4. **NOT approval:** User's original request ("scan this codebase"), silence, questions about the plan

### Pre-Scan Checklist

Before marking Step 3 complete:
- [ ] Target directory shown to user
- [ ] Engine type (Pro/OSS) displayed
- [ ] Languages detected and listed
- [ ] **All rulesets explicitly listed with checkboxes**
- [ ] User given opportunity to modify rulesets
- [ ] User explicitly approved (quote their confirmation)
- [ ] **Final ruleset list captured for Step 4**
- [ ] Agent type listed: `static-analysis:semgrep-scanner`

### Log Approved Rulesets

After approval, write the approved rulesets to `$OUTPUT_DIR/rulesets.txt`:

```bash
cat > "$OUTPUT_DIR/rulesets.txt" << RULESETS
# Semgrep Scan — Approved Rulesets
# Generated: $(date -Iseconds)
# Scan mode: <run-all|important-only>

## Rulesets:
<one ruleset per line, e.g.:>
p/security-audit
p/secrets
p/python
p/django
https://github.com/trailofbits/semgrep-rules
RULESETS
```

---

## Step 4: Run the Scan Workflow

> **Entry:** Step 3 approved — user explicitly confirmed the plan.
> **Exit:** The workflow returned a result object; result files exist in `$OUTPUT_DIR/raw/`.

Call the `Workflow` tool with `scriptPath` set to
`{baseDir}/workflows/semgrep-scan.js` and this as `args`:

```json
{
  "target": "<absolute path to the scan target>",
  "outputDir": "<absolute path to $OUTPUT_DIR>",
  "mode": "run-all",
  "pro": true,
  "rulesets": {
    "baseline": ["p/security-audit", "p/secrets"],
    "python": ["p/python", "p/django"],
    "javascript": ["p/javascript"],
    "docker": ["p/dockerfile"],
    "third_party": ["https://github.com/trailofbits/semgrep-rules"]
  }
}
```

`rulesets` is the structured JSON from Step 2, exactly as the user approved it in Step 3. Pass
it through unchanged. `mode` is `run-all` or `important-only`. Both paths must be absolute;
the workflow throws on a relative one rather than letting a subagent resolve it somewhere else.

Repository URLs go under `third_party` and nowhere else. A `https://…` filed under a language
key fails the registry-identifier check and throws, and Step 4's rule is to report the message
and stop rather than retry, so a plan the user already approved dies and they are sent back
through the hard gate over a misfiled key.

`pro` is the boolean from Step 1's Pro check, not the `true` in the example above. It puts
`--pro` on every command, so sending `true` after Step 1 printed `Pro: NOT AVAILABLE` fails
every scan in the run and the report shows a total failure with no hint that one field caused
it. The workflow throws on a non-boolean rather than reading `"false"` as true, but it cannot
tell a wrong boolean from a right one.

This skill being invoked, and the Step 3 gate being passed, is the opt-in the `Workflow` tool
needs.

The workflow clones each third-party repo once, then runs one agent per language plus one for
the cross-language rulesets. It builds every `semgrep` command itself, so `--metrics=off`, the
`--include` scoping rule, and the severity flags are not yours to add. It returns:

| Field | Meaning |
|-------|---------|
| `scans` | Rulesets that ran, with `json`, `sarif`, and `findings` for each |
| `failed` | Rulesets that ran and did not produce usable output, with the `json` and `sarif` paths they may have partly written. **Must be shown to the user.** |
| `skipped` | Rulesets dropped before scanning, mostly repos that would not clone. **Must be shown.** |
| `unscoped` | Languages with no `--include` map, which ran against every file |
| `alsoShared` | Rulesets dropped from a language because the same ruleset is already running unscoped over the whole target. Coverage is unaffected; report them so a per-ruleset accounting adds up |
| `reposPath` | The clone directory Step 5 deletes |

**The call does not return the result object.** `Workflow` starts the run in the background and
hands back a task id; the result arrives later, when the run completes. Do not begin Step 5 on
what the tool call returned. Wait for the completion notification, and read `scans`, `failed`,
and `skipped` from that. Treating the task id as an empty result is how a scan that is still
running gets reported as a scan that found nothing.

**If the workflow threw**, Step 4 did not run. `semgrep-scan.js` validates its arguments
before spawning anything, and every one of those checks fires after the user has already
passed the hard gate. Report the thrown message verbatim, say that no scan ran, and stop; do
not retry with adjusted arguments, because the approved plan is what produced them.

**Once you hold the result:** if `scans` is empty, the scan did not happen. Say so and stop
rather than reporting zero findings. If `failed` or `skipped` is non-empty, carry both into the
Step 5 report. A run that covered four of nine rulesets reads exactly like one that covered four
of four unless you say otherwise.

### Fallback: no `Workflow` tool

If the `Workflow` tool is unavailable, or the script path does not resolve, do the same work
inline. It is slower and the invariants are back on you.

Spawn N agents in a SINGLE message (one per language category, plus one cross-language) with
`subagent_type: static-analysis:semgrep-scanner`, using the prompt templates in
[scanner-task-prompt.md](../references/scanner-task-prompt.md). The spawn tool is `Agent` on
some builds and `Task` on others; SKILL.md allows both, because this path exists for the case
where `Workflow` is missing and being blocked on the tool name would leave no path at all.
Observe:

- Always use **absolute paths** for `[TARGET]` — subagents can't resolve relative paths
- Clone GitHub URL rulesets into `$OUTPUT_DIR/repos/<owner>-<repo>` — never pass URLs directly
  to `--config` (semgrep's URL handling fails on repos with non-standard YAML), and include the
  owner in the directory name because several organizations publish a repo named `semgrep-rules`
- Clone once, before spawning the scanners, and delete `$OUTPUT_DIR/repos/` in Step 5. Do not
  put the `rm -rf` in the scanner prompt: each agent only knows when its own scans finish, so
  the first to finish deletes the rules the others are still reading
- Run rulesets in parallel with `&` and `wait`, not sequentially, but in batches of at most 4
  per scanner: every scanner is doing this at once, and semgrep processes that get OOM-killed
  report back as scan failures with nothing pointing at memory as the cause
- Use `--include="*.py"` for language-specific rulesets, but NOT for cross-language rulesets
  (p/security-audit, p/secrets, third-party repos)
- Add `--exclude="<$OUTPUT_DIR relative to $TARGET>"` to **every** command when `$OUTPUT_DIR` is
  inside `$TARGET`, which is the default. The workflow path does this itself; here it is on you.
  Without it the cross-language rulesets scan the cloned rule repos and the raw output of
  sibling scanners, so the report fills with findings that are not in the user's code
- Run each cross-language ruleset once rather than once per language
- **Important only**: add `--severity WARNING --severity ERROR` to every
  `semgrep` command. **Run all**: no additional flags

---

## Step 5: Merge Results and Report

> **Entry:** Step 4 complete — the workflow returned.
> **Exit:** `results.sarif` exists in `$OUTPUT_DIR/results/` and is valid JSON; `repos/` deleted.

**First, confirm each `scans` entry actually wrote its files.** Every entry is a scanner
agent's own report that its scan succeeded, and nothing has checked it — the workflow script
has no filesystem access. Test each entry's own `json` and `sarif` path with `[ -s ... ]`.
Do not compare a count of files in `raw/` against the length of `scans`: aggregates cancel, so
one agent inventing a success for a scan that wrote nothing plus one `failed` scan that
crashed after writing gives the same total as a healthy run. Treat any entry whose files are
missing as failed for the rest of Step 5 and list it under "Did Not Run".

**Important-only mode: Post-filter before merge.** Apply the filter from [scan-modes.md](../references/scan-modes.md) ("Filter All Result Files in a Directory" section) to each result JSON in `$OUTPUT_DIR/raw/`. The filter creates `*-important.json` files alongside the originals — the originals are preserved unmodified.

**Generate merged SARIF** using the merge script. The resolved path is in SKILL.md's "Merge command" section — use that exact path:

```bash
uv run {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif"
```

- **Run-all mode:** The script merges all `*.sarif` files from `$OUTPUT_DIR/raw/`.
- **Important-only mode:** Run the post-filter first (creates `*-important.json` in `raw/`), then run the merge script. Raw SARIF files are unaffected by the JSON post-filter, so the merge operates on the unfiltered SARIF. For SARIF-level filtering, apply the jq post-filter from scan-modes.md to `$OUTPUT_DIR/results/results.sarif` after merge.

**Verify merged SARIF is valid:**

```bash
python -c "import json; d=json.load(open('$OUTPUT_DIR/results/results.sarif')); print(f'{sum(len(r.get(\"results\",[]))for r in d.get(\"runs\",[]))} findings in merged SARIF')"
```

If verification fails, the merge script produced invalid output — investigate before reporting.

**Delete the cloned rulesets** once the merge has succeeded. The workflow clones each
third-party repo into `repos/` and leaves it there for the scanners; this is the only place
the deletion happens, and nothing that reads it is still running by now.

```bash
[ -n "$OUTPUT_DIR" ] && rm -rf "$OUTPUT_DIR/repos"
```

**Report to user:**

```
## Semgrep Scan Complete

**Scanned:** 1,804 files
**Rulesets used:** 9 (including Trail of Bits)
**Total findings:** 156   [count this from results.sarif, never by summing scans[].findings:
one finding flagged by two rulesets is one row in the merge and two in that sum]

### By Severity:
- ERROR: 5
- WARNING: 18
- INFO: 9

### By Category:
- SQL Injection: 3
- XSS: 7
- Hardcoded secrets: 2
- Insecure configuration: 12
- Code quality: 8

### Did Not Run:
[omit this section only when failed and skipped are both empty]
- Skipped: <ruleset> — <reason from the workflow>
- Failed: <ruleset> — <error from the workflow>

### Also Covered Unscoped:
[omit when alsoShared is empty]
- <ruleset> — already running over the whole target from the baseline, so it was not scanned
  again under <language>. Coverage is unaffected; this is why the ruleset count and the scan
  count differ

### Ran Unscoped:
[omit when unscoped is empty]
- <language> — no --include map, so its rulesets ran against every file

Results written to:
- $OUTPUT_DIR/results/results.sarif (merged SARIF)
- $OUTPUT_DIR/raw/ (per-scan raw results, unfiltered)
- $OUTPUT_DIR/rulesets.txt (approved rulesets)
```

**Verify** before reporting: confirm `results.sarif` exists and is valid JSON.
