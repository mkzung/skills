# Static Analysis

A comprehensive static analysis toolkit with CodeQL, Semgrep, and SARIF parsing for security vulnerability detection.

CodeQL and Semgrep skills are based on the Trail of Bits Testing Handbook:

- [CodeQL Testing Handbook](https://appsec.guide/docs/static-analysis/codeql/)
- [Semgrep Testing Handbook](https://appsec.guide/docs/static-analysis/semgrep/)

**Author:** Axel Mierczuk & Paweł Płatek

## Skills Included

| Skill           | Purpose                                                  |
|-----------------|----------------------------------------------------------|
| `codeql`        | Deep security analysis with taint tracking and data flow |
| `semgrep`       | Fast pattern-based security scanning                     |
| `sarif-parsing` | Parse and process results from static analysis tools     |

## When to Use

Use this plugin when you need to:
- Perform security vulnerability detection on codebases
- Run CodeQL for interprocedural taint tracking and data flow analysis
- Use Semgrep for fast pattern-based bug detection
- Parse SARIF output from security scanners
- Aggregate and deduplicate findings from multiple tools

## What It Does

### CodeQL
- Create databases for Python, JavaScript, Go, Java, C/C++, and more
- Run security queries with SARIF/CSV output
- Generate data extension models for project-specific APIs
- Select and combine query packs (security-extended, Trail of Bits, Community)

### Semgrep
- Quick security scans using built-in rulesets (OWASP, CWE, Trail of Bits)
- Write custom YAML rules with pattern matching
- Taint mode for tracking data flow from sources to sinks
- CI/CD integration with baseline scanning

### SARIF Parsing
- Understand SARIF 2.1.0 structure
- Quick analysis using jq for CLI queries
- Python scripting with pysarif and sarif-tools
- Aggregate and deduplicate results from multiple files
- CI/CD integration patterns

## Workflows Included

| Workflow                    | Purpose                                                          |
|-----------------------------|------------------------------------------------------------------|
| `skills/semgrep/workflows/semgrep-scan.js` | Builds every semgrep command from the approved rulesets and runs them in parallel, one agent per language plus one for the cross-language rules |

The semgrep skill calls it in Step 4, after the user approves the scan plan. Generating the
commands in JavaScript is what makes `--metrics=off`, the `--include` scoping rule, and the
parallel dispatch properties of the code rather than instructions an agent can drop. Unit tests
in `tests/semgrep-scan.test.mjs` stub every agent and assert those properties directly.

## Agents Included

| Agent              | Tools                     | Purpose                                                        |
|--------------------|---------------------------|----------------------------------------------------------------|
| `semgrep-scanner`  | Bash, StructuredOutput    | Runs the semgrep commands the scan workflow generates          |

`StructuredOutput` is how the agent returns its verdict when the workflow calls it with a
schema. See the comment on the `tools:` list in `agents/semgrep-scanner.md` before removing it.

## Installation

```
/plugin install trailofbits/skills/plugins/static-analysis
```

## Related Skills

- `variant-analysis` - Use CodeQL/Semgrep patterns to find bug variants
