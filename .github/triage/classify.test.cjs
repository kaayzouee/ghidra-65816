const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { issueLabels, pathLabels, classify, createMissing } = require('./classify.cjs');
const catalog = require('./labels.json');
const triage = 'status: needs-triage';
const docs = 'type: documentation';
const label = name => ({ name, node_id: 'LA_' + name });
const file = filename => ({ filename, status: 'modified' });
const http = status => Object.assign(new Error('sensitive server response'), { status });
const base = { number: 12, node_id: 'I_12', state: 'open', labels: [] };
const issue = (areas, type = 'bug') => ({ ...base, labels: [label('type: ' + type)],
  body: '### Technical areas\n\n' + areas + '\n\n### ' +
    (type === 'bug' ? 'Summary' : 'Problem or use case') + '\n\nExample' });
const pr = count => ({ ...base, node_id: 'PR_12', changed_files: count,
  base: { ref: 'master', sha: 'base' }, head: { ref: '${{ secrets.BAD }}', sha: 'head', repo: { fork: true } } });

test('both forms identify type and offer catalog areas, documentation and unsure', () => {
  for (const [form, type] of [['bug_report', 'bug'], ['feature_request', 'feature']]) {
    const text = fs.readFileSync('.github/ISSUE_TEMPLATE/' + form + '.yml', 'utf8').replaceAll('\r', '');
    assert.match(text, new RegExp('^labels: .*"type: ' + type + '"', 'm'));
    assert.deepEqual([...text.matchAll(/^        - ([a-z-]+)$/gm)].map(m => m[1]),
      [...Object.keys(catalog.area.labels), 'documentation', 'unsure']);
    assert.deepEqual(issueLabels(issue('ci', type)), ['area: ci']);
    const report = issue('documentation, ci, tests', type);
    report.body = report.body.replaceAll('\n', '\r\n');
    assert.deepEqual(issueLabels(report), [docs, 'area: ci', 'area: tests']);
  }
});

test('ambiguous, missing, injected and legacy data defer', () => {
  for (const area of ['ci, unsure', 'pcode, typo', 'priority: critical', '', 'constructor',
    '${{ secrets.GITHUB_TOKEN }}', '$(exit 1)', 'pcode\nmore']) assert.deepEqual(issueLabels(issue(area)), []);
  for (const body of [null, '', '### Area\n\nTests / CI', issue('ci').body + '\n### Technical areas\n\npcode']) {
    assert.deepEqual(issueLabels({ ...issue('ci'), body }), []);
  }
  assert.deepEqual(issueLabels({ ...issue('ci'), labels: [] }), []);
  const report = issue('ci');
  report.labels.push(label('type: feature'));
  assert.deepEqual(issueLabels(report), []);
});

test('documentation requires both sides of every path to qualify', () => {
  assert.deepEqual(pathLabels([file('README.md'), file('CONTRIBUTORS')]), [docs]);
  assert.deepEqual(pathLabels([file('README.md'), file('data/languages/65816.slaspec')]), ['area: sleigh']);
  assert.deepEqual(pathLabels([{ filename: 'docs/a.md', previous_filename: 'unmatched' }]), []);
  assert.deepEqual(pathLabels([file('.github/ISSUE_TEMPLATE/config.yml')]), ['area: ci']);
  assert.deepEqual(pathLabels([{ filename: 'unknown', previous_filename: 'data/languages/65816.cspec' },
    { filename: 'data/languages/658xx_memaccess_pc.sinc', status: 'removed' }]).sort(),
    ['area: control-flow', 'area: decompiler', 'area: memory', 'area: pcode', 'area: sleigh']);
  assert.deepEqual(pathLabels([file('unknown/$(touch secret)')]), []);
  for (const name of Object.keys(require('./paths.json'))) {
    const [prefix, suffix] = name.split(': ');
    assert.ok(prefix === 'area' || name === docs);
    assert.ok(Object.hasOwn(catalog[prefix].labels, suffix));
  }
});

function fixture(opened = issue('ci')) {
  const live = structuredClone(opened);
  live.labels.push(label('priority: high'));
  const entries = [triage, 'area: ci', docs].map(label);
  const events = [], files = [], failures = [], output = [], writes = [];
  const summary = {
    addHeading(s) { output.push(s); return this; },
    addRaw(s) { output.push(s); return this; },
    async write() {}
  };
  const issues = {
    get: async () => ({ data: live }),
    listLabelsForRepo: () => entries,
    listEvents: () => events,
    createLabel: async ({ name }) => { const data = label(name); entries.push(data); return { data }; },
    getLabel: async ({ name }) => ({ data: entries.find(e => e.name === name) })
  };
  const pulls = { listFiles: () => files, get: async () => ({ data: live }) };
  const github = {
    rest: { issues, pulls },
    async paginate(endpoint, params, map) {
      assert.equal(params.per_page, 100);
      const data = endpoint();
      const result = [];
      for (let i = 0; i < data.length; i += 100) {
        const page = data.slice(i, i + 100);
        result.push(...(map ? map({ data: page }) : page));
      }
      return result;
    },
    async graphql(query, { item, labels }) {
      assert.match(query, /addLabelsToLabelable/);
      assert.equal(item, opened.node_id);
      for (const id of labels) {
        const entry = entries.find(e => e.node_id === id);
        assert.ok(entry);
        if (!live.labels.some(e => e.node_id === id)) live.labels.push(entry);
        events.push({ event: 'labeled', label: { name: entry.name } });
      }
      writes.push(...labels);
      return { addLabelsToLabelable: { labelable: { id: item } } };
    }
  };
  const payload = opened.head ? { pull_request: opened } : { issue: opened };
  const args = { github, context: { repo: { owner: 'owner', repo: 'repo' }, payload },
    core: { summary, warning: s => output.push(s), setFailed: s => failures.push(s) } };
  return { args, live, entries, events, files, failures, output, writes, issues, pulls };
}

test('fork metadata and paginated files include late-page matches and triage', async () => {
  const f = fixture(pr(101));
  for (let i = 0; i < 100; i++) f.files.push(file('unknown/' + i));
  f.files.push(file('.github/workflows/sleigh.yml'));
  await classify(f.args);
  assert.deepEqual(f.writes, [label(triage).node_id, label('area: ci').node_id]);
  assert.deepEqual(f.failures, []);
});

for (const reason of ['unmatched', 'limit', 'short page', 'head changed', 'base changed', 'duplicate', 'malformed', '403']) {
  test('PR keeps triage when ' + reason, async () => {
    const f = fixture(pr(reason === 'limit' ? 3000 : ['short page', 'duplicate'].includes(reason) ? 2 : 1));
    f.files.push(file(reason === 'unmatched' ? 'unknown' : 'README.md'));
    if (reason === 'head changed') f.live.head.sha = 'new';
    if (reason === 'base changed') f.live.base.sha = 'new';
    if (reason === 'duplicate') f.files.push(file('README.md'));
    if (reason === 'malformed') f.files[0] = { status: 'renamed', filename: 'README.md' };
    if (reason === '403') f.pulls.listFiles = () => { throw http(403); };
    await classify(f.args);
    assert.deepEqual(f.writes, [label(triage).node_id]);
    assert.equal(f.failures.length, ['403', 'malformed'].includes(reason) ? 1 : 0);
    assert.ok(!f.output.join('').includes('sensitive server response'));
  });
}

test('edited body and missing submission type defer to triage only', async () => {
  for (const edit of [true, false]) {
    const report = issue('ci');
    if (!edit) report.labels = [];
    const f = fixture(report);
    if (edit) f.live.body = issue('documentation').body;
    await classify(f.args);
    assert.deepEqual(f.writes, [label(triage).node_id]);
  }
});

test('case variants resolve by ID; ambiguous IDs fail without modification', async () => {
  const report = issue('ci');
  report.labels[0].name = 'TYPE: BUG';
  const f = fixture(report);
  f.entries[1].name = 'Area: CI';
  await classify(f.args);
  assert.ok(f.writes.includes(label('area: ci').node_id));
  f.entries.push({ name: 'AREA: CI', node_id: 'distinct' });
  await classify(f.args);
  assert.equal(f.failures.length, 1);
  assert.equal(f.writes.length, 2);
});

test('missing labels fail visibly; rerun fills only missing work', async () => {
  const f = fixture(issue('documentation, ci, tests'));
  await classify(f.args);
  assert.equal(f.failures.length, 1);
  assert.ok(f.output.includes('Missing: area: tests'));
  const before = f.writes.length;
  f.entries.push(label('area: tests'));
  await classify(f.args);
  await classify(f.args);
  assert.deepEqual(f.writes.slice(before), [label('area: tests').node_id]);
  assert.ok(f.live.labels.some(l => l.name === 'priority: high'));
});

test('removal, including a renamed label, hands the entire item to humans', async () => {
  const f = fixture();
  f.events.push({ event: 'unlabeled', label: { name: 'OLD NAME' } });
  await classify(f.args);
  assert.deepEqual(f.writes, []);
  assert.ok(f.output.includes('Prior removal or closure. All labeling decisions preserved.'));
});

test('interrupted write, rerun and concurrent attempts converge', async () => {
  const f = fixture();
  const add = f.args.github.graphql;
  f.args.github.graphql = async (...args) => { await add(...args); throw http(503); };
  await classify(f.args);
  assert.equal(f.failures.length, 1);
  f.args.github.graphql = add;
  await Promise.all([classify(f.args), classify(f.args)]);
  assert.equal(f.writes.length, 2);
  const fresh = fixture();
  await Promise.all([classify(fresh.args), classify(fresh.args)]);
  assert.deepEqual(fresh.live.labels.map(l => l.name).sort(), ['area: ci','priority: high',triage,'type: bug'].sort());
});

test('history errors fail closed; transient failures recover on explicit rerun', async () => {
  const f = fixture();
  const read = f.issues.listEvents;
  f.issues.listEvents = () => { throw http(429); };
  await classify(f.args);
  assert.deepEqual(f.writes, []);
  assert.match(f.failures[0], /429/);
  f.issues.listEvents = read;
  await classify(f.args);
  assert.equal(f.writes.length, 2);
});

test('malformed history or mutation response fails visibly', async () => {
  const f = fixture();
  f.events.push({});
  await classify(f.args);
  assert.equal(f.writes.length, 0);
  f.events.length = 0;
  f.args.github.graphql = async () => ({});
  await classify(f.args);
  assert.equal(f.failures.length, 2);
});

test('administrative creation recovers from partial failure and a concurrent create', async () => {
  const f = fixture();
  f.entries.push(label('Type: Bug'));
  const create = f.issues.createLabel;
  f.issues.createLabel = async p => {
    if (p.name === 'type: feature') throw http(403);
    await create(p);
    if (p.name === 'type: enhancement') throw http(422);
  };
  await createMissing(f.args);
  assert.equal(f.failures.length, 1);
  assert.ok(f.output.includes('Created concurrently: type: enhancement'));
  f.issues.createLabel = create;
  await createMissing(f.args);
  await createMissing(f.args);
  assert.equal(f.entries.length, 36);
  assert.ok(f.output.includes('Created: 0. Skipped: 36. Conflicting: 0.'));
  assert.ok(f.entries.some(l => l.name === 'Type: Bug'));
});

test('failed file read recovers on rerun without duplicating initial triage', async () => {
  const f = fixture(pr(1));
  const read = f.pulls.listFiles;
  f.pulls.listFiles = () => { throw http(503); };
  f.files.push(file('README.md'));
  await classify(f.args);
  f.pulls.listFiles = read;
  await classify(f.args);
  assert.deepEqual(f.writes, [label(triage).node_id, label(docs).node_id]);
});

test('historical assignments and removal of triage survive job replay', async () => {
  const f = fixture();
  f.events.push({ event: 'labeled', label: { name: 'AREA: CI' } });
  await classify(f.args);
  assert.deepEqual(f.writes, [label(triage).node_id]);
  f.live.labels = f.live.labels.filter(l => l.name !== triage);
  f.events.push({ event: 'unlabeled', label: { name: triage } });
  await classify(f.args);
  assert.deepEqual(f.writes, [label(triage).node_id]);
  assert.ok(f.live.labels.some(l => l.name === 'priority: high'));
});

test('provisioning reports ambiguous IDs and preserves both existing entries', async () => {
  const f = fixture();
  f.entries.push({ name: 'AREA: CI', node_id: 'other' });
  await createMissing(f.args);
  assert.equal(f.entries.filter(e => e.name.toLowerCase() === 'area: ci').length, 2);
  assert.equal(f.failures.length, 1);
  assert.ok(f.output.some(s => s.includes('Conflicting: 1.')));
});
