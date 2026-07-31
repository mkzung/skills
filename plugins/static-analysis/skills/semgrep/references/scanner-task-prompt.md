# Scanner Subagent Task Prompt (fallback path)

Step 4 normally runs `workflows/semgrep-scan.js`, which generates these commands itself. This
template is for the fallback path, when the `Workflow` tool is unavailable and the skill spawns
scanners directly with `subagent_type: static-analysis:semgrep-scanner`.

Two things the workflow does that this template leaves to you: clone each third-party repo once
before spawning any scanner and delete `repos/` in Step 5 rather than inside a scanner, and run
each cross-language ruleset once rather than once per language.

## Template

```
You are a Semgrep scanner for [LANGUAGE_CATEGORY].

## Task
Run Semgrep scans for [LANGUAGE] files and save results to [OUTPUT_DIR]/raw.

## Pro Engine Status: [PRO_AVAILABLE: true/false]

## Scan Mode: [SCAN_MODE: run-all/important-only]

## APPROVED RULESETS (from user-confirmed plan)
[LIST EXACT RULESETS USER APPROVED - DO NOT SUBSTITUTE]

Example:
- p/python
- p/django
- p/security-audit
- p/secrets
- https://github.com/trailofbits/semgrep-rules

Third-party rulesets have already been cloned to [OUTPUT_DIR]/repos/[owner]-[repo]. Use those
local paths as --config values. Do not clone anything, and do not delete that directory: other
scanners are reading it, and the caller removes it in Step 5.

## Commands to Run (in parallel, at most 4 at a time)

### Generate commands for EACH approved ruleset:
```bash
semgrep [--pro if available] --metrics=off [SEVERITY_FLAGS] [INCLUDE_FLAGS] [EXCLUDE_FLAG] --config [RULESET] --json -o [OUTPUT_DIR]/raw/[lang]-[ruleset].json --sarif-output=[OUTPUT_DIR]/raw/[lang]-[ruleset].sarif [TARGET] &
```

Capture each pid and wait on it by pid, at most 4 per batch, before emitting the next batch:
```bash
semgrep ... & p1=$!
semgrep ... & p2=$!
wait $p1; echo "rc <ruleset1> $?"
wait $p2; echo "rc <ruleset2> $?"
```

A bare `wait` returns one status for the whole batch, so a ruleset that exited 7 because its
config would not load is indistinguishable from three that scanned cleanly. You can still
recover the truth from the JSON files, but only if you go looking; the per-pid form tells you.

## Critical Rules
- Use ONLY the rulesets listed above - do not add or remove any
- Always use --metrics=off (prevents sending telemetry to Semgrep servers)
- If `[OUTPUT_DIR]` is inside `[TARGET]` (the default, since it is created in the CWD), put `--exclude` on **every** command. Without it the cross-language rulesets scan `repos/`, which holds thousands of third-party rule files full of literal example secrets and deliberately vulnerable snippets, and `raw/*.json` that sibling scanners are still writing. Both fill the report with findings that are not in the user's code, and the second makes two runs of the same scan disagree. If `[OUTPUT_DIR]` *equals* `[TARGET]`, stop and ask for a different output directory
- Use --pro when Pro is available (enables cross-file taint tracking)
- If scan mode is **important-only**, add `--severity WARNING --severity ERROR` to every command
- If scan mode is **run-all**, do NOT add severity flags
- Run rulesets in parallel in batches of at most 4, capturing each pid and waiting on it by pid. Every scanner you spawned is doing the same thing at the same time, and semgrep holds the rules and the scanned ASTs in memory: an unbounded fan-out gets processes OOM-killed, and those come back as scan failures with no hint that the cause was memory. A bare `wait` gives you one status for the batch and hides which ruleset failed
- Pass the local clone path as --config, never the GitHub URL (semgrep's URL handling is unreliable for repos with non-standard YAML)
- Add `--include` flags for language-specific rulesets (e.g., `--include="*.py"` for p/python). Do NOT add `--include` to cross-language rulesets like p/security-audit, p/secrets, or third-party repos
- The exit code says nothing about findings: on semgrep 1.168 a scan that found nothing and one that found forty both exit 0. Count findings from the JSON. Exit 7 (config would not load) and 2 (bad argument, missing target) mean no scan happened; treat 0 and 1 as successful scans

## Output
Report:
- Number of findings per ruleset
- Any scan errors
- File paths of JSON results (in [OUTPUT_DIR]/raw/)
- [If Pro] Note any cross-file findings detected

Report every ruleset you were given, including ones that failed. A ruleset missing from your
report reads to the caller as one that was never requested.
```

## Variable Substitutions

| Variable | Description | Example |
|----------|-------------|---------|
| `[LANGUAGE_CATEGORY]` | Language group being scanned | Python, JavaScript, Docker |
| `[LANGUAGE]` | Specific language | Python, TypeScript, Go |
| `[OUTPUT_DIR]` | Output directory (absolute path, resolved in Step 1) | /path/to/static_analysis_semgrep_1 |
| `[PRO_AVAILABLE]` | Whether Pro engine is available | true, false |
| `[SEVERITY_FLAGS]` | Severity pre-filter flags | *(empty)* for run-all, `--severity WARNING --severity ERROR` for important-only |
| `[INCLUDE_FLAGS]` | File extension filter for language-specific rulesets | `--include="*.py"` for Python rulesets, *(empty)* for cross-language rulesets like p/security-audit, p/secrets, or third-party repos |
| `[EXCLUDE_FLAG]` | `--exclude="<OUTPUT_DIR relative to TARGET>"` when `[OUTPUT_DIR]` sits inside `[TARGET]`, *(empty)* otherwise. **On every command, including the cross-language ones** | `--exclude="static_analysis_semgrep_1"` |
| `[RULESET]` | Semgrep ruleset identifier or local clone path | p/python, [OUTPUT_DIR]/repos/trailofbits-semgrep-rules |
| `[owner]-[repo]` | Clone directory for a third-party repo. Owner included because several organizations publish a repo named `semgrep-rules` | trailofbits-semgrep-rules, elttam-semgrep-rules |
| `[TARGET]` | Absolute path to directory to scan | /path/to/codebase |

## Two kinds of task

Spawn one task per detected language, **plus one cross-language task**. Both examples are
below. Spawning only the language tasks is the failure this section exists to prevent: the
baseline and third-party rulesets are the ones SKILL.md calls required, and they belong to
neither language, so they get scanned by nobody.

## Example: Python Scanner Task

Note what is *not* here: `p/security-audit`, `p/secrets`, and the Trail of Bits repo. Those
scan the whole target unscoped, so they go to the cross-language task below, not into every
language task writing a duplicate under a different name.

```
You are a Semgrep scanner for Python.

## Task
Run Semgrep scans for Python files and save results to /path/to/static_analysis_semgrep_1/raw.

## Pro Engine Status: true

## Scan Mode: run-all

## APPROVED RULESETS (from user-confirmed plan)
- p/python
- p/django

## Commands to Run (in parallel, at most 4 at a time)

```bash
semgrep --pro --metrics=off --include="*.py" --config p/python --json -o /path/to/static_analysis_semgrep_1/raw/python-python.json --sarif-output=/path/to/static_analysis_semgrep_1/raw/python-python.sarif /path/to/codebase &
p1=$!
semgrep --pro --metrics=off --include="*.py" --config p/django --json -o /path/to/static_analysis_semgrep_1/raw/python-django.json --sarif-output=/path/to/static_analysis_semgrep_1/raw/python-django.sarif /path/to/codebase &
p2=$!
wait $p1; echo "rc p/python $?"
wait $p2; echo "rc p/django $?"
```

## Critical Rules
- Use ONLY the rulesets listed above - do not add or remove any
- Always use --metrics=off
- Use --pro when Pro is available
- Run rulesets in parallel, at most 4 at a time, waiting on each by pid
- Add --include="*.py" to language-specific rulesets (p/python, p/django) but NOT to p/security-audit, p/secrets, or third-party repos
- Do not clone anything and do not delete repos/; the caller owns both

## Output
Report:
- Number of findings per ruleset
- Any scan errors
- File paths of JSON results (in raw/ subdirectory)
- Note any cross-file findings detected
```

## Example: Cross-Language Scanner Task

One of these per run, alongside the language tasks. It holds the rulesets that have no
language: the baseline packs and every third-party repo. Nothing here takes `--include`, and
the output stems start with `all-` so they cannot collide with a language task's files.

```
You are a Semgrep scanner for the cross-language rulesets.

## Task
Run Semgrep scans against the whole target and save results to /path/to/static_analysis_semgrep_1/raw.

## Pro Engine Status: true

## Scan Mode: run-all

## APPROVED RULESETS (from user-confirmed plan)
- p/security-audit
- p/secrets
- https://github.com/trailofbits/semgrep-rules (already cloned to /path/to/static_analysis_semgrep_1/repos/trailofbits-semgrep-rules)

## Commands to Run (in parallel, at most 4 at a time)

```bash
semgrep --pro --metrics=off --config p/security-audit --json -o /path/to/static_analysis_semgrep_1/raw/all-security-audit.json --sarif-output=/path/to/static_analysis_semgrep_1/raw/all-security-audit.sarif /path/to/codebase &
p1=$!
semgrep --pro --metrics=off --config p/secrets --json -o /path/to/static_analysis_semgrep_1/raw/all-secrets.json --sarif-output=/path/to/static_analysis_semgrep_1/raw/all-secrets.sarif /path/to/codebase &
p2=$!
semgrep --pro --metrics=off --config /path/to/static_analysis_semgrep_1/repos/trailofbits-semgrep-rules --json -o /path/to/static_analysis_semgrep_1/raw/all-trailofbits-semgrep-rules.json --sarif-output=/path/to/static_analysis_semgrep_1/raw/all-trailofbits-semgrep-rules.sarif /path/to/codebase &
p3=$!
wait $p1; echo "rc p/security-audit $?"
wait $p2; echo "rc p/secrets $?"
wait $p3; echo "rc trailofbits-semgrep-rules $?"
```

## Critical Rules
- No --include on any of these. They carry rules for every language, and a filter would drop findings in files it does not match
- Pass the clone path as --config, never the GitHub URL
- Run each of these once for the whole run, not once per language
- Do not clone anything and do not delete repos/; the caller owns both

## Output
Report:
- Number of findings per ruleset
- Any scan errors
- File paths of JSON results (in raw/ subdirectory)
```
