const { matchesGlob } = require('node:path').posix;
const catalog = require('./labels.json');
const paths = require('./paths.json');

const triage = 'status: needs-triage';
const docs = 'type: documentation';
const definitions = Object.entries(catalog).flatMap(([prefix, { color, labels }]) =>
  Object.entries(labels).map(([suffix, description]) => ({ name: prefix + ': ' + suffix, color, description })));
const areaNames = Object.keys(catalog.area.labels).map(area => 'area: ' + area);
const automatic = new Set([triage, docs, ...areaNames]);

function issueLabels(issue) {
  const types = issue.labels.map(label => label.name.toLowerCase()).filter(name => name.startsWith('type: ') && name !== docs);
  if (types.length !== 1 || !['type: bug', 'type: feature'].includes(types[0])) return [];
  const body = (issue.body ?? '').replaceAll('\r\n', '\n');
  if (body.match(/^### Technical areas\s*$/gm)?.length !== 1) return [];
  const field = /^### Technical areas\n\n([^\n]+)\n\n### ([^\n]+)(?:\n|$)/u.exec(body);
  const next = types[0] === 'type: bug' ? 'Summary' : 'Problem or use case';
  if (!field || field[2] !== next) return [];
  const choices = field[1].split(',').map(s => s.trim());
  if (!choices.every(s => s === 'documentation' || Object.hasOwn(catalog.area.labels, s))) return [];
  return [...new Set(choices.map(s => s === 'documentation' ? docs : 'area: ' + s))];
}

function pathLabels(files) {
  const names = files.flatMap(f => f.previous_filename ? [f.filename, f.previous_filename] : [f.filename]);
  if (!names.length) return [];
  return Object.entries(paths).filter(([label, patterns]) => {
    const matches = name => patterns.some(p => matchesGlob(name, p));
    return label === docs ? names.every(matches) : names.some(matches);
  }).map(([name]) => name);
}

function indexLabels(labels) {
  const index = new Map();
  for (const { name, node_id } of labels) {
    if (typeof name !== 'string' || !node_id) throw Error('Invalid repository label');
    const key = name.toLowerCase();
    const ids = index.get(key) ?? new Set();
    ids.add(node_id);
    index.set(key, ids);
  }
  return index;
}

function status(error) {
  return Number.isInteger(error?.status) ? ' (HTTP ' + error.status + ')' : '';
}

async function prLabels(github, repo, opened) {
  const params = { ...repo, pull_number: opened.number };
  if (opened.changed_files >= 3000) return null;
  const files = await github.paginate(github.rest.pulls.listFiles, { ...params, per_page: 100 },
    page => page.data.map(({ filename, previous_filename, status }) => {
      if (!filename || typeof filename !== 'string' || (status === 'renamed' && !previous_filename)) {
        throw Error('Invalid file record');
      }
      return { filename, previous_filename };
    }));
  const { data: live } = await github.rest.pulls.get(params);
  if (!opened.head?.sha || !opened.base?.sha || opened.head.sha !== live.head.sha ||
      opened.base.sha !== live.base.sha || live.base.ref !== 'master' || files.length >= 3000 ||
      live.changed_files !== files.length || new Set(files.map(f => f.filename)).size !== files.length ||
      (opened.changed_files != null && opened.changed_files !== files.length)) return null;
  return pathLabels(files);
}

async function classify({ github, context, core }) {
  const { issue, pull_request: pr } = context.payload;
  const item = issue ?? pr;
  const summary = core.summary.addHeading('Opening triage #' + item.number);
  const note = (title, names) => summary.addRaw(title + ': ' + (names.join(', ') || 'none'), true);
  const params = { ...context.repo, per_page: 100 };
  const target = { ...context.repo, issue_number: item.number };
  let stage = 'reading item';
  try {
    const { data: live } = await github.rest.issues.get(target);
    if (live.node_id !== item.node_id || !['open', 'closed'].includes(live.state)) throw Error();
    if (live.state !== 'open') {
      summary.addRaw('Item is no longer open. No changes.', true);
      return;
    }
    let components = [];
    if (pr) {
      try {
        const result = await prLabels(github, context.repo, pr);
        if (result === null) {
          core.warning('Incomplete or changed PR snapshot. Review paths manually.');
          summary.addRaw('Only triage requested. Check the complete current diff manually.', true);
        } else components = result;
      } catch (error) {
        core.setFailed('Could not read PR files or metadata' + status(error) + '. Attempting triage only.');
        summary.addRaw('File lookup failed. Attempting triage only.', true);
      }
    } else if (issue.body === live.body) {
      const accepted = new Set(issueLabels(live));
      components = issueLabels(issue).filter(name => accepted.has(name));
    }
    if (issue && !components.length) summary.addRaw('Form evidence missing, edited or ambiguous. Review manually.', true);
    const candidates = [triage, ...components];
    if (!candidates.every(name => automatic.has(name))) throw Error();
    note('Candidates', candidates);
    stage = 'reading repository labels';
    const index = indexLabels(await github.paginate(github.rest.issues.listLabelsForRepo, params));
    stage = 'checking label history';
    const history = await github.paginate(github.rest.issues.listEvents, { ...target, per_page: 100 },
      page => page.data.map(({ event, label }) => {
        if (typeof event !== 'string') throw Error();
        return { event, label };
      }));
    // A removal hands the entire item to the reviewer, including labels renamed since removal.
    if (history.some(e => ['unlabeled', 'closed'].includes(e.event))) {
      summary.addRaw('Prior removal or closure. All labeling decisions preserved.', true);
      return;
    }
    const current = new Set(live.labels.map(label => label.name.toLowerCase()));
    const past = new Set(history.filter(e => e.event === 'labeled').map(e => e.label.name.toLowerCase()));
    const pending = new Map();
    const existing = [], historical = [], missing = [], conflicts = [];
    for (const name of candidates) {
      const ids = index.get(name);
      if (ids?.size > 1) conflicts.push(name);
      else if (current.has(name)) existing.push(name);
      else if (past.has(name)) historical.push(name);
      else if (!ids) missing.push(name);
      else pending.set(name, [...ids][0]);
    }
    note('Already present', existing);
    note('Preserved from history', historical);
    note('Missing', missing);
    note('Conflicting', conflicts);
    if (missing.length || conflicts.length) core.setFailed('Resolve catalog entries and rerun the failed job.');
    if (pending.size) {
      stage = 'adding existing label IDs';
      const result = await github.graphql(`mutation($item: ID!, $labels: [ID!]!) {
        addLabelsToLabelable(input: {labelableId: $item, labelIds: $labels}) { labelable { ... on Node { id } } }
      }`, { item: item.node_id, labels: [...pending.values()] });
      if (result?.addLabelsToLabelable?.labelable?.id !== item.node_id) throw Error();
    }
    note('Applied', [...pending.keys()]);
  } catch (error) {
    core.setFailed('Classification failed while ' + stage + status(error) + '.');
    summary.addRaw('Could not verify completion while ' + stage + status(error) + '.', true);
  } finally {
    await summary.addRaw('Recovery: inspect current labels, resolve the failure and rerun the failed job or finish triage manually.', true).write();
  }
}

async function createMissing({ github, context, core }) {
  const summary = core.summary.addHeading('Triage label provisioning');
  const { issues } = github.rest;
  const params = { ...context.repo, per_page: 100 };
  let created = 0, skipped = 0, conflicts = 0;
  let operation = 'listing repository labels';
  try {
    const index = indexLabels(await github.paginate(issues.listLabelsForRepo, params));
    const missing = definitions.filter(label => !index.has(label.name));
    summary.addRaw('Initially missing: ' + (missing.map(l => l.name).join(', ') || 'none'), true);
    for (const label of definitions) {
      const ids = index.get(label.name);
      if (ids?.size > 1) {
        conflicts++;
        summary.addRaw('Ambiguous repository entries for ' + label.name, true);
        core.setFailed('Resolve ambiguous entries manually.');
      } else if (ids) skipped++;
      else {
        try {
          operation = 'creating ' + label.name;
          const { data } = await issues.createLabel({ ...context.repo, ...label });
          if (data?.name?.toLowerCase() !== label.name || !data.node_id) throw Error();
          created++;
        } catch (error) {
          if (error.status !== 422) throw error;
          const { data } = await issues.getLabel({ ...context.repo, name: label.name });
          if (data.name.toLowerCase() !== label.name || !data.node_id) throw error;
          skipped++;
          summary.addRaw('Created concurrently: ' + label.name, true);
        }
      }
    }
  } catch (error) {
    core.setFailed('Provisioning incomplete while ' + operation + status(error) + '. Redispatch after resolving the failure.');
    summary.addRaw('Stopped while ' + operation + status(error) + '. Check permissions or rate limits and redispatch.', true);
  } finally {
    await summary.addRaw(`Created: ${created}. Skipped: ${skipped}. Conflicting: ${conflicts}.`, true).write();
  }
}

module.exports = { issueLabels, pathLabels, classify, createMissing };
