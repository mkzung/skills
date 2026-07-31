export const meta = {
  name: 'semgrep-scan',
  description:
    'Runs an approved set of Semgrep rulesets across the detected languages in parallel and reports what each scan produced.',
  whenToUse:
    'Invoked by the semgrep skill after the user approves the scan plan. Execution only: it selects no rulesets and reports nothing to the user.',
  // No `phases`. Both phase() calls are conditional — Clone only fires when the plan carries
  // third-party repos, Scan only when there is a unit to run — and a phase declared here but
  // never entered shows in the progress display as a group that never starts, which is the
  // same "reads as hung" appearance the guards on those calls exist to avoid. A phase() call
  // with no matching meta entry gets its own group when it fires.
}

// Semgrep sends telemetry by default and `--config auto` phones home. This flag is
// concatenated into every command below and is deliberately not a parameter: a scan
// running during a security audit must never be one forgotten argument away from
// uploading the client's file paths.
const METRICS_OFF = '--metrics=off'

// semgrep's --severity filter accepts INFO, WARNING, and ERROR, and rejects anything
// else with exit code 2 before scanning. The rule metadata uses LOW/MEDIUM/HIGH and the
// registry's rule severity adds CRITICAL, which is where the old MEDIUM/HIGH/CRITICAL
// spelling came from; it never reached a scan. Dropping INFO is what important-only
// wanted, and the metadata thresholds are applied by the post-filter in scan-modes.md.
const SEVERITY_FLAGS = ['--severity WARNING', '--severity ERROR']

const MODES = new Set(['run-all', 'important-only'])

// Keys in the rulesets object that name a scope rather than a language. Both hold rules
// for every language at once, so restricting them with --include would silently drop
// findings in files the current language filter does not match.
const BASELINE_KEY = 'baseline'
const THIRD_PARTY_KEY = 'third_party'

// Past this many languages the batches grow rather than the fleet, so a monorepo costs
// the same number of agents as a two-language service.
const MAX_SCAN_AGENTS = 8

// MAX_SCAN_AGENTS bounds agents, not processes: each agent backgrounds every command it
// holds, so 8 agents holding 10 rulesets each is 80 concurrent scans. semgrep keeps the rules
// and the scanned ASTs in memory, and an OOM-killed scan reports back as ok=false with no
// sign that memory was the cause. Each agent runs its commands in batches of this size.
const MAX_PARALLEL_SCANS_PER_AGENT = 4

// The --include globs each language-scoped ruleset is restricted to. This lives here
// rather than arriving in args because it is the rule the prose kept restating in four
// different wordings; a map cannot be misread.
//
// The extensions are the ones semgrep parses for that language, checked on semgrep 1.168.0 by
// scanning a directory holding one file per extension. Re-run that check when bumping semgrep:
// a file type this map omits is excluded from the scan with no signal in the report, so the
// ruleset comes back ok=true with zero findings and reads as clean.
//
// Absent because 1.168 does not parse them, not by oversight: `.mts`, `.cts`, and `.C`.
// Adding a glob for any of those would scope a scan to files semgrep then refuses to read.
//
// `javascript` carries the TypeScript extensions because the two docs that produce a plan
// disagree: scan-workflow.md's Step 1 table emits one JavaScript/TypeScript category, while
// rulesets.md lists `.js/.jsx` and `.ts/.tsx` as separate rows. Both shapes reach this map, so
// a plan that names only `javascript` still has to scan `.ts`. FALLBACK_INCLUDES takes the
// TypeScript globs back when a plan names both.
const LANGUAGE_INCLUDES = {
  python: ['*.py', '*.pyi'],
  javascript: ['*.js', '*.jsx', '*.mjs', '*.cjs', '*.ts', '*.tsx'],
  typescript: ['*.ts', '*.tsx'],
  go: ['*.go'],
  ruby: ['*.rb'],
  java: ['*.java', '*.jsp'],
  kotlin: ['*.kt', '*.kts'],
  php: ['*.php', '*.phtml'],
  c: ['*.c', '*.h'],
  cpp: ['*.c', '*.cc', '*.cpp', '*.cxx', '*.h', '*.hh', '*.hpp', '*.hxx'],
  csharp: ['*.cs'],
  rust: ['*.rs'],
  scala: ['*.scala'],
  swift: ['*.swift'],
  elixir: ['*.ex', '*.exs'],
  solidity: ['*.sol'],
  // These two are the whole list, checked on 1.168 by scanning a directory of one file per
  // name with no filter at all: `Dockerfile` and `app.dockerfile` are parsed, and
  // `dockerfile`, `Dockerfile.prod` and `Containerfile` are not. Adding globs for the latter
  // three would scope a scan to files semgrep then refuses to read, which reports as zero
  // findings and reads like a clean result. A Podman repo using `Containerfile` gets no
  // dockerfile coverage from semgrep at all; that is a semgrep limitation, not this map's.
  docker: ['Dockerfile', '*.dockerfile'],
  terraform: ['*.tf', '*.tfvars', '*.hcl'],
  // These four are recommended by references/rulesets.md and had no entry, so a plan naming
  // them ran its rulesets against every file in the tree. Extensions are the ones that doc
  // names; `json` and `apex` are semgrep languages, and cloudformation/github-actions are
  // ruleset packs over YAML and JSON rather than languages of their own.
  json: ['*.json'],
  apex: ['*.cls', '*.trigger'],
  cloudformation: ['*.yaml', '*.yml', '*.json'],
  'github-actions': ['*.yml', '*.yaml'],
  // Identical to `yaml` on purpose: a Kubernetes manifest is a YAML file and no extension
  // separates the two. Both keys carry different rulesets over the same files.
  kubernetes: ['*.yaml', '*.yml'],
  yaml: ['*.yaml', '*.yml'],
}

const LANGUAGE_ALIASES = {
  js: 'javascript',
  jsx: 'javascript',
  tsx: 'typescript',
  ts: 'typescript',
  'js/ts': 'javascript',
  'javascript/typescript': 'javascript',
  node: 'javascript',
  nodejs: 'javascript',
  golang: 'go',
  'c/c++': 'cpp',
  'c++': 'cpp',
  cxx: 'cpp',
  dockerfile: 'docker',
  k8s: 'kubernetes',
  'c#': 'csharp',
  dotnet: 'csharp',
  sol: 'solidity',
  tf: 'terraform',
  hcl: 'terraform',
  cfn: 'cloudformation',
  'github actions': 'github-actions',
  githubactions: 'github-actions',
  gha: 'github-actions',
  salesforce: 'apex',
}

// Object.hasOwn, not `LANGUAGE_ALIASES[k] || k`: a key of `constructor` or `toString` picks up
// an inherited property, and the function that comes back is used as a language name.
const canonicalLanguage = (key) => {
  const k = String(key).trim().toLowerCase()
  return Object.hasOwn(LANGUAGE_ALIASES, k) ? LANGUAGE_ALIASES[k] : k
}

const includesFor = (lang) =>
  Object.hasOwn(LANGUAGE_INCLUDES, lang) ? LANGUAGE_INCLUDES[lang] : undefined

// The language half of every output filename. Only the stem is slugged, not the label the
// report shows: an unrecognized key like `k8s/yaml` would otherwise reach
// `-o ".../raw/k8s/yaml-p-kubernetes.json"`, a directory that does not exist, and the ruleset
// would fail with an error pointing at nothing.
const slugLang = (lang) =>
  lang
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'lang'

// The lang prefix the cross-language unit stems its output filenames from.
const SHARED_LANG = 'all'

const SCAN_SCHEMA = {
  type: 'object',
  required: ['scans'],
  additionalProperties: false,
  properties: {
    scans: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'ruleset', 'ok', 'findings', 'error'],
        additionalProperties: false,
        properties: {
          id: {
            type: 'string',
            description:
              'the id from the `# id:` comment directly above the command you ran. This is the ' +
              'key the caller matches on, and it is unique per scan where the ruleset name is ' +
              'not: one ruleset can be scanned under two languages with different --include flags.',
          },
          ruleset: {
            type: 'string',
            description: 'the --config value exactly as it appeared in the command you ran',
          },
          ok: {
            type: 'boolean',
            description:
              'true only when semgrep exited 0 or 1 AND both output files exist. Exit 0 covers ' +
              'both "found nothing" and "found plenty" on current semgrep, so it says nothing ' +
              'about findings; exit 7 (config would not load) and 2 (bad argument or missing ' +
              'target) mean no scan happened. A ruleset that failed to download, crashed, or ' +
              'wrote nothing is ok=false. Never omit it from this list, since a missing entry ' +
              'reads to the caller as a scan that was never requested rather than one that failed.',
          },
          findings: {
            type: 'integer',
            description: 'count of .results in the JSON output, or -1 when ok is false',
          },
          error: { type: 'string', description: 'stderr excerpt when ok is false, else ""' },
        },
      },
    },
  },
}

const CLONE_SCHEMA = {
  type: 'object',
  required: ['cloned'],
  additionalProperties: false,
  properties: {
    cloned: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'ok', 'error'],
        additionalProperties: false,
        properties: {
          name: { type: 'string', description: 'the directory name from the clone command' },
          ok: { type: 'boolean', description: 'true only when the clone directory now holds rule files' },
          error: { type: 'string', description: 'stderr excerpt when ok is false, else ""' },
        },
      },
    },
  },
}

// ------------------------------------------------------------------ arguments

const target = args && args.target
const outputDir = args && args.outputDir
const mode = args && args.mode
const rulesets = (args && args.rulesets) || {}

// Every one of these throws rather than degrading. A scan that runs with no rulesets, or
// against a relative path a subagent resolves differently than the caller did, produces a
// clean-looking empty report, the single most expensive failure this plugin can have.
// Both paths are spliced into the same double-quoted commands the ruleset strings are, so
// they need the same treatment. A denylist rather than an allowlist, because paths have no
// narrow shape the way `p/python` does: `;`, `&`, `|`, spaces and parentheses are all inert
// inside double quotes and all appear in real directory names, so rejecting them would fail
// legitimate scans. These four are the ones that stay live between double quotes, and a
// control character can smuggle a newline into the command block.
const SHELL_UNSAFE = /["$`\\]|[\x00-\x1f]/
const checkPath = (name, value) => {
  if (typeof value !== 'string' || !value.startsWith('/')) {
    throw new Error(`${name} must be an absolute path, got ${JSON.stringify(value)}`)
  }
  const bad = value.match(SHELL_UNSAFE)
  if (bad) {
    throw new Error(
      `${name} contains ${JSON.stringify(bad[0])}, which stays live inside the double quotes ` +
        `it is spliced into: ${JSON.stringify(value)}`,
    )
  }
}
checkPath('target', target)
// outputDir is the stricter of the two in consequence: besides the scan commands it reaches
// mkdir -p, the git clone destination, and the caller's `rm -rf "$OUTPUT_DIR/repos"`.
checkPath('outputDir', outputDir)
if (!MODES.has(mode)) {
  throw new Error(`mode must be one of ${[...MODES].join(', ')}, got ${JSON.stringify(mode)}`)
}

// `pro` decides whether every command gets --pro, which selects a different engine. Truthiness
// would read the string "false" as true, so a caller that stringifies its booleans would turn
// Pro on against the intent recorded in the plan the user approved.
if (args && args.pro !== undefined && typeof args.pro !== 'boolean') {
  throw new Error(`pro must be a boolean, got ${JSON.stringify(args.pro)}`)
}
const pro = Boolean(args && args.pro)

// Strings have a .length and are iterable, so a single ruleset written without the brackets
// (`"docker": "p/dockerfile"`) would pass a length check and then expand through
// `new Set(...)` into one --config per character. The caller composing this JSON is a model,
// which makes that slip likely enough to reject outright.
for (const [key, value] of Object.entries(rulesets)) {
  if (!Array.isArray(value)) {
    throw new Error(`rulesets.${key} must be an array, got ${JSON.stringify(value)}`)
  }
}

// Every ruleset string ends up spliced into a shell command an agent is told to run exactly
// as written, and double quotes do not neutralize $() or backticks. Registry identifiers are
// `p/python`, `r/json.aws` and the like, so anything outside this set is not a ruleset.
// Shell-safe is the first job, but the error message says "registry identifier", so the
// pattern should mean it: no leading slash and no `..` segment. Without those, `/etc` and
// `p/python/../../..` pass and reach `--config`, where semgrep exits 7 and the ruleset lands
// in `failed` with an error that points at nothing recognizable.
const RULESET_ID = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/
for (const [key, values] of Object.entries(rulesets)) {
  if (key === THIRD_PARTY_KEY) continue
  for (const ruleset of values) {
    const bad =
      typeof ruleset !== 'string' ||
      !RULESET_ID.test(ruleset) ||
      ruleset.split('/').includes('..')
    if (bad) {
      throw new Error(
        `rulesets.${key} entries must be registry identifiers like p/python, got ${JSON.stringify(ruleset)}`,
      )
    }
  }
}

// Repository URLs get their own shape, for the same reason: they end up in a `git clone` line.
const GIT_URL = /^https:\/\/[A-Za-z0-9.-]+(:\d+)?(\/[A-Za-z0-9._-]+)+(\.git)?\/?$/
for (const url of rulesets[THIRD_PARTY_KEY] || []) {
  if (typeof url !== 'string' || !GIT_URL.test(url)) {
    throw new Error(`third_party entries must be https git URLs, got ${JSON.stringify(url)}`)
  }
}

const languageKeys = Object.keys(rulesets).filter(
  (k) => k !== BASELINE_KEY && k !== THIRD_PARTY_KEY && rulesets[k].length > 0,
)

// The keys get the same treatment as the values. Every ruleset string and both paths are
// checked against a denylist because they are spliced into a double-quoted shell command an
// agent runs verbatim; the key is spliced into the same command, as the language half of
// `-o "<rawDir>/<lang>-<ruleset>.json"`. It arrives as free-form model output, so `py$(id)`
// is the same exposure one field over.
//
// The allowed set is wider than RULESET_ID because real category names carry `/`, `#` and `+`:
// `JavaScript/TypeScript`, `c#`, `c++`. Those are safe inside double quotes, and slugLang
// keeps them out of the filename.
const LANGUAGE_KEY = /^[A-Za-z0-9 ._+#/-]+$/
for (const key of languageKeys) {
  if (!LANGUAGE_KEY.test(key)) {
    throw new Error(
      `rulesets keys name a language and reach the scan command as a filename; ${JSON.stringify(key)} is not one`,
    )
  }
}

// Checked on the slug rather than the canonical name, because that is what actually collides:
// a key of `all/` canonicalizes to `all/` and passes an equality check, then slugs to `all`
// and lands on the cross-language unit's filenames, where uniqueStem gives it a -2 suffix and
// one scan shows up as two rows in the report. Checked here with the other arguments so a bad
// plan throws before the clone phase has fetched anything.
for (const key of languageKeys) {
  if (slugLang(canonicalLanguage(key)) === SHARED_LANG) {
    throw new Error(
      `rulesets.${key} names the reserved language "${SHARED_LANG}", which the cross-language unit uses ` +
        'for its output filenames',
    )
  }
}

// Language keys are not required. Baseline and third-party rulesets scan the whole target
// unscoped, so a plan holding only those is a complete scan, not an unscopable one: a user
// who clears every language ruleset at the approval gate and keeps the baseline still gets
// the cross-language unit. The only unrunnable plan is an empty one.
const crossLanguageCount =
  (rulesets[BASELINE_KEY] || []).length + (rulesets[THIRD_PARTY_KEY] || []).length
if (languageKeys.length === 0 && crossLanguageCount === 0) {
  throw new Error('rulesets holds no entries at all; there is nothing to scan')
}

const rawDir = `${outputDir}/raw`
const reposPath = `${outputDir}/repos`

// The default $OUTPUT_DIR is created in the CWD, which for the ordinary invocation ("scan this
// repo" from its root) puts it inside `target`. Without an --exclude, every scan also scans the
// run's own artifacts: the cloned third-party rule repos, which are thousands of YAML files
// holding literal example secrets and deliberately vulnerable snippets, and the raw/*.json that
// other agents are still writing. Checked on semgrep 1.168 — p/secrets flags the rule files,
// and because the raw outputs appear as other agents finish, the finding set changes between
// runs of the same scan.
//
// Scoped to the case where outputDir is genuinely inside target. Excluding the basename
// unconditionally would also drop an unrelated directory of the same name elsewhere in the tree.
const targetRoot = target.replace(/\/+$/, '')
const outputRoot = outputDir.replace(/\/+$/, '')
if (outputRoot === targetRoot) {
  throw new Error(
    `outputDir is the scan target (${outputDir}); the run would scan its own output and its cloned rules`,
  )
}
const excludes = outputRoot.startsWith(`${targetRoot}/`)
  ? [outputRoot.slice(targetRoot.length + 1)]
  : []
if (excludes.length > 0) {
  // semgrep --exclude takes a path pattern, not a path rooted at the target. Checked on 1.168:
  // `out/scan1`, `./out/scan1` and `/out/scan1` all also exclude `vendor/out/scan1`, so there
  // is no anchored form to use. Over-excluding is the safer direction than scanning the run's
  // own cloned rules, but it can skip real code, so the pattern is named in the log rather
  // than applied quietly. A single-segment default like `static_analysis_semgrep_1` is
  // unlikely to collide; a nested user-supplied directory is likelier to.
  log(
    `output directory is inside the target: excluding "${excludes[0]}" from every scan. ` +
      'semgrep matches that pattern anywhere in the tree, so a directory of the same name ' +
      'elsewhere under the target is skipped too.',
  )
}

// -------------------------------------------------------------------- helpers

// Globs one language carries only to cover for another the plan may not name. `javascript`
// scans `.ts` so a plan that folds TypeScript into it still scans TypeScript; once the plan
// names `typescript`, keeping them on both scans every `.ts` file twice.
//
// One entry, because there is one such relationship. Overlap on its own does not imply a
// fallback: `cpp` carries `*.c` and `*.h` because a C++ project's headers are `.h` and its
// sources can be `.c`, and `p/cpp` rules have to see those files whether or not the plan also
// names `c`. Subtracting every overlap would take them away.
const FALLBACK_INCLUDES = {
  javascript: { typescript: ['*.ts', '*.tsx'] },
}

function narrowIncludes(langs) {
  const present = new Set(langs.filter((lang) => includesFor(lang)))
  const out = new Map()
  for (const lang of present) {
    const drop = new Set()
    for (const [covers, globs] of Object.entries(FALLBACK_INCLUDES[lang] || {})) {
      if (present.has(covers)) for (const g of globs) drop.add(g)
    }
    const kept = includesFor(lang).filter((g) => !drop.has(g))
    // A language with no globs runs against every file, which is worse than the overlap.
    out.set(lang, kept.length > 0 ? kept : includesFor(lang))
  }
  return out
}

// Filenames, not identifiers: `p/security-audit` and a clone path must both reduce to
// something safe to concatenate into a shell-quoted path. Repository URLs carry the owner
// through for the same reason repoDirName does, so `all-trailofbits-semgrep-rules.sarif`
// and `all-elttam-semgrep-rules.sarif` stay tellable apart in the raw directory.
function slug(ruleset) {
  if (ruleset.includes('://')) return repoDirName(ruleset)
  const base = ruleset.startsWith('/') ? ruleset.split('/').pop() : ruleset
  return base
    .replace(/^[a-z]+\//, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

// Several organizations publish a repository literally named `semgrep-rules` (Trail of
// Bits, 0xdea, and elttam among them), so the clone directory must carry the owner too.
// Keying on the basename alone would have the second clone fail into a non-empty
// directory and the third scan somebody else's rules under the first one's name.
function repoDirName(url) {
  const parts = url.replace(/\.git$/, '').replace(/\/+$/, '').split('/')
  const repo = parts.pop() || 'rules'
  const owner = parts.pop() || 'unknown'
  return `${owner}-${repo}`.replace(/[^A-Za-z0-9._-]+/g, '-')
}

const usedNames = new Set()
function uniqueStem(lang, ruleset) {
  const base = `${slugLang(lang)}-${slug(ruleset)}`
  if (!usedNames.has(base)) {
    usedNames.add(base)
    return base
  }
  let n = 2
  while (usedNames.has(`${base}-${n}`)) n++
  usedNames.add(`${base}-${n}`)
  return `${base}-${n}`
}

function buildScan({ lang, ruleset, config, includes }) {
  const stem = uniqueStem(lang, ruleset)
  const json = `${rawDir}/${stem}.json`
  const sarif = `${rawDir}/${stem}.sarif`
  const parts = ['semgrep']
  if (pro) parts.push('--pro')
  parts.push(METRICS_OFF)
  if (mode === 'important-only') parts.push(...SEVERITY_FLAGS)
  for (const glob of includes) parts.push(`--include="${glob}"`)
  // Before --config, and on every command including the unscoped cross-language ones: those
  // are the rulesets that would otherwise scan the cloned rule repos.
  for (const path of excludes) parts.push(`--exclude="${path}"`)
  parts.push(`--config "${config}"`)
  parts.push(`--json -o "${json}"`)
  parts.push(`--sarif-output="${sarif}"`)
  parts.push(`"${target}"`)
  return { id: stem, lang, ruleset, config, json, sarif, command: parts.join(' ') }
}

// Round-robin into exactly min(buckets, items.length) groups. Slicing into fixed-size chunks
// returns ceil(n / ceil(n/buckets)) groups, which is often fewer than asked for: 9 languages
// into 7 buckets gives 5 agents of 2, so two thirds of the fleet the cap allows goes unused and
// the run takes longer than it needs to.
function chunk(items, buckets) {
  const n = Math.min(buckets, items.length)
  if (n <= 0) return []
  const out = Array.from({ length: n }, () => [])
  items.forEach((item, i) => out[i % n].push(item))
  return out
}

// ------------------------------------------------------- phase 1: clone

// Deduplicated by clone directory rather than by exact string. The destination and the
// verdict lookup are both keyed on repoDirName, which strips `.git` and trailing slashes, so
// two spellings of one repository survive a string Set but collide on one directory: the
// second clone fails into a non-empty tree and both URLs then read the same verdict.
const thirdPartyUrls = []
const seenRepoDirs = new Set()
for (const url of rulesets[THIRD_PARTY_KEY] || []) {
  const name = repoDirName(url)
  if (seenRepoDirs.has(name)) continue
  seenRepoDirs.add(name)
  thirdPartyUrls.push(url)
}

const skipped = []
const clonedConfigs = new Map()

if (thirdPartyUrls.length > 0) {
  // Inside the branch: with no third-party repos there is no clone agent, and an empty phase
  // group in the progress display reads as a step that hung rather than one that never ran.
  phase('Clone')
  // Each destination is cleared first. `git clone` refuses a non-empty directory, so a reused
  // $OUTPUT_DIR would fail the clone and drop an approved ruleset as `skipped` while usable
  // rules sat on disk. The path is `${outputDir}/repos/<owner>-<repo>`: outputDir has been
  // through checkPath and the last segment through repoDirName, so neither half can walk out
  // of the run's own directory.
  const cloneLines = thirdPartyUrls.flatMap((url) => [
    `rm -rf "${reposPath}/${repoDirName(url)}"`,
    `git clone --depth 1 "${url}" "${reposPath}/${repoDirName(url)}"`,
  ])
  const cloneResult = await agent(
    [
      'Clone the Semgrep rule repositories below, then report what each one produced.',
      '',
      `mkdir -p "${reposPath}"`,
      ...cloneLines,
      '',
      'Run exactly these commands. Do not add repositories, change a destination, or retry',
      'with a different URL. A clone that fails is a result to report, not a problem to work',
      'around: the caller drops that repository from the scan and tells the user it was',
      'skipped, which is the honest outcome. Substituting a different source would put rules',
      'the user never approved into a scan they did approve.',
      '',
      'Confirm rule files actually landed before reporting ok=true for any of them:',
      ...thirdPartyUrls.map(
        (url) => `  find "${reposPath}/${repoDirName(url)}" \\( -name '*.yaml' -o -name '*.yml' \\) | head -1`,
      ),
      'An empty clone directory is ok=false. A repository that cloned but carries no rules',
      'scans nothing, and reporting it as fine would show the user a completed scan against',
      'a ruleset that never ran.',
    ].join('\n'),
    { label: 'clone', schema: CLONE_SCHEMA },
  )

  const byName = new Map()
  if (cloneResult && Array.isArray(cloneResult.cloned)) {
    for (const c of cloneResult.cloned) byName.set(c.name, c)
  }

  for (const url of thirdPartyUrls) {
    const name = repoDirName(url)
    const report = byName.get(name)
    // A dead clone agent leaves `report` undefined for every repository. Treating that as
    // success would hand the scan phase a --config path that does not exist; treating it
    // as silence would drop the ruleset without telling anyone. It is a skip, and skips
    // are returned to the caller.
    if (report && report.ok) {
      clonedConfigs.set(url, `${reposPath}/${name}`)
    } else {
      skipped.push({
        ruleset: url,
        reason: report ? report.error || 'clone reported not ok' : 'clone agent returned no verdict',
      })
    }
  }
  log(`third-party repos: ${clonedConfigs.size} cloned, ${skipped.length} skipped`)
}

// -------------------------------------------------------- build the scan list

// Cross-language rulesets run unscoped over the whole target, so running them once per
// language ran the identical command N times and leaned on the SARIF merge to dedup the
// copies. They get one unit.
const sharedScans = []
for (const ruleset of [...new Set(rulesets[BASELINE_KEY] || [])]) {
  sharedScans.push(buildScan({ lang: SHARED_LANG, ruleset, config: ruleset, includes: [] }))
}
for (const url of thirdPartyUrls) {
  const config = clonedConfigs.get(url)
  if (!config) continue
  sharedScans.push(buildScan({ lang: SHARED_LANG, ruleset: url, config, includes: [] }))
}

// Keys are merged by canonical name before any unit exists. `js` and `javascript` in one plan
// are the same language, and a unit per raw key gives two agents with the same label and the
// same --include set. A ruleset named under both then runs twice under different stems, and
// Step 5 adds both findings counts into a total that is too high.
const byLanguage = new Map()
for (const key of languageKeys) {
  const lang = canonicalLanguage(key)
  byLanguage.set(lang, (byLanguage.get(lang) || []).concat(rulesets[key]))
}

// A ruleset already running unscoped over the whole target does not need a second, narrower
// run. A user who adds `p/secrets` to the Python list at the approval gate while it is also in
// `baseline` would otherwise get `all-secrets` and `python-secrets`, both landing in `scans`
// with their own counts. The merged SARIF dedups them; a per-scan sum does not.
const sharedRulesets = new Set(sharedScans.map((s) => s.config))
const alsoShared = []

// Two passes, because narrowing has to know which languages actually end up with a scan.
// FALLBACK_INCLUDES strips `*.ts` from `javascript` when `typescript` is present; if the
// typescript unit is then emptied by the shared-ruleset dedup, nothing scans `.ts` at all and
// the log line names a language no agent ran. Same trap the `unscoped` push avoids.
//
// Pass 1: drop rulesets already running unscoped over the whole target, and keep only the
// languages that still have something of their own. Deduplicated per language too, because
// verdicts come back keyed on the scan id: the same ruleset listed twice for one language
// would scan twice and the second copy's failure would read as the first copy's success.
const surviving = new Map()
for (const [lang, rulesetList] of byLanguage) {
  const own = [...new Set(rulesetList)].filter((ruleset) => {
    if (!sharedRulesets.has(ruleset)) return true
    alsoShared.push(`${lang}/${ruleset}`)
    return false
  })
  if (own.length > 0) surviving.set(lang, own)
}

// Pass 2: narrow and build, over the survivors only.
const unscoped = []
const narrowedIncludes = narrowIncludes([...surviving.keys()])
const languageUnits = [...surviving].map(([lang, own]) => {
  const includes = narrowedIncludes.get(lang)
  // An unrecognized language name costs the --include optimization, not coverage: the rules
  // run against every file and fail to match the ones they do not understand. Degrading
  // quietly would still be wrong, so it is logged and returned.
  if (!includes) unscoped.push(lang)
  return {
    label: lang,
    scans: own.map((ruleset) => buildScan({ lang, ruleset, config: ruleset, includes: includes || [] })),
  }
})

if (alsoShared.length > 0) {
  log(`already running unscoped, so not scanned again per language: ${alsoShared.join(', ')}`)
}

if (unscoped.length > 0) {
  log(`no --include globs for ${unscoped.join(', ')}; those rulesets run against every file`)
}

// Narrowing changes which files a ruleset sees, so it names the globs it gave up.
const trimmed = [...narrowedIncludes].filter(([lang, globs]) => globs.length !== includesFor(lang).length)
for (const [lang, globs] of trimmed) {
  const dropped = includesFor(lang).filter((g) => !globs.includes(g))
  log(`${lang} no longer scans ${dropped.join(' ')}; the plan names those languages itself`)
}

// The cross-language unit counts against the cap. It joins the list after batching, so
// chunking the languages into the full cap would spawn MAX_SCAN_AGENTS + 1 agents.
const languageAgentCap = Math.max(1, MAX_SCAN_AGENTS - (sharedScans.length > 0 ? 1 : 0))
const batched =
  languageUnits.length <= languageAgentCap
    ? languageUnits.map((u) => [u])
    : chunk(languageUnits, languageAgentCap)

const units = batched.map((group) => ({
  label: group.map((u) => u.label).join('+'),
  scans: group.flatMap((u) => u.scans),
}))
if (sharedScans.length > 0) units.unshift({ label: 'cross-language', scans: sharedScans })

if (languageUnits.length > languageAgentCap) {
  log(`${languageUnits.length} languages batched into ${batched.length} agents`)
}
log(`${units.length} scan agents, ${units.reduce((n, u) => n + u.scans.length, 0)} scans`)

// ------------------------------------------------------------- phase 2: scan

// Guarded for the same reason phase('Clone') is. A plan of third-party repos that all failed
// to clone leaves no units, so an unconditional call shows an empty Scan group in the progress
// display, which reads as a step that hung rather than one that never ran.
if (units.length > 0) phase('Scan')

function scanPrompt(unit) {
  const batches = []
  for (let i = 0; i < unit.scans.length; i += MAX_PARALLEL_SCANS_PER_AGENT) {
    batches.push(unit.scans.slice(i, i + MAX_PARALLEL_SCANS_PER_AGENT))
  }
  return [
    `Run the Semgrep scans below for ${unit.label}, then report what each produced.`,
    '',
    `mkdir -p "${rawDir}"`,
    '',
    `Run the ${batches.length} ${batches.length === 1 ? 'batch' : 'batches'} below in order. Everything inside a batch runs in`,
    'parallel; each batch must finish before the next one starts. Do not flatten them into one',
    'fan-out: several agents are running alongside you, and semgrep holds the rules and the',
    'scanned ASTs in memory, so the processes that get killed come back to the caller as scan',
    'failures with nothing pointing at memory as the cause.',
    '',
    'Each command captures its pid and is waited on by pid. A bare `wait` returns one status for',
    'the whole batch, so three healthy scans and one that exited 7 would be indistinguishable',
    'from four healthy ones. The `rc <id> <code>` lines are where you read each exit code.',
    '',
    ...batches.flatMap((batch, i) => [
      `# batch ${i + 1} of ${batches.length}`,
      ...batch.flatMap((s, j) => [`# id: ${s.id}`, `${s.command} &`, `p${j + 1}=$!`]),
      ...batch.map((s, j) => `wait $p${j + 1}; echo "rc ${s.id} $?"`),
      '',
    ]),
    'Run them exactly as written. The rulesets, the flags, and the output paths were all',
    'fixed by the caller from a list the user approved by hand. Adding a ruleset scans rules',
    'the user declined; dropping one leaves a gap the report will present as clean.',
    '',
    'The exit code does not tell you whether anything was found: on semgrep 1.168 a scan that',
    'found nothing and a scan that found forty both exit 0. Take the count from the JSON. A',
    'non-zero code means the scan did not happen: 7 for a config that would not load, 2 for a',
    'bad argument or a missing target. Report ok=true for exit 0 or 1 with both output files',
    'present, ok=false for anything else.',
    '',
    'Report every scan in the list, including the ones that failed. Count findings with:',
    `  jq '.results | length' "<the .json path from the command>"`,
    '',
    'Report each scan under the id from the `# id:` comment directly above its command. The',
    'ruleset name alone is not unique: one ruleset can appear twice in this list under two',
    'languages with different --include flags, and the caller cannot tell those apart.',
  ].join('\n')
}

const results = await parallel(
  units.map((unit) => () =>
    agent(scanPrompt(unit), {
      label: `scan:${unit.label}`,
      agentType: 'static-analysis:semgrep-scanner',
      schema: SCAN_SCHEMA,
    }).then((r) => ({ unit, report: r })),
  ),
)

// ------------------------------------------------------------------- assemble

const scans = []
const failed = []

for (let i = 0; i < units.length; i++) {
  const unit = units[i]
  const settled = results[i]
  const report = settled && settled.report

  // A unit whose agent died reports nothing at all. Every ruleset it was holding has to
  // surface as failed: leaving them out would shrink the denominator, and a scan that
  // covered four of nine rulesets would read exactly like one that covered four of four.
  // `failed` carries the same paths `scans` does. A scan that crashed part-way may still have
  // written a partial file, so the caller needs the path to name it in the report rather than
  // reporting a ruleset that failed with no way to find what it left behind.
  if (!report || !Array.isArray(report.scans)) {
    for (const s of unit.scans) {
      failed.push({
        lang: s.lang,
        ruleset: s.ruleset,
        json: s.json,
        sarif: s.sarif,
        error: `scan agent for ${unit.label} returned nothing`,
      })
    }
    continue
  }

  // Keyed on the scan id, not the --config value. Dedup runs per language, but a unit can
  // hold several languages once chunk() batches them, and two languages may legitimately
  // share a ruleset with different --include flags. Keying on the config would collapse
  // those two scans onto one verdict, so a crashed scan would inherit the other's success.
  const byId = new Map()
  for (const r of report.scans) byId.set(r.id, r)

  for (const s of unit.scans) {
    const r = byId.get(s.id)
    if (r && r.ok) {
      scans.push({ lang: s.lang, ruleset: s.ruleset, json: s.json, sarif: s.sarif, findings: r.findings })
    } else {
      failed.push({
        lang: s.lang,
        ruleset: s.ruleset,
        json: s.json,
        sarif: s.sarif,
        error: r ? r.error || 'scan reported not ok' : 'no verdict returned for this ruleset',
      })
    }
  }
}

log(`${scans.length} scans succeeded, ${failed.length} failed, ${skipped.length} skipped`)

return { outputDir, rawDir, reposPath, mode, pro, scans, failed, skipped, unscoped, alsoShared }
