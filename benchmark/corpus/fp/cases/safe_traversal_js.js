// Negative fixture for the path-traversal rule family (ZS-JS-024/025/032/
// 062/063/064/065/091). Every filesystem path below is a constant. What is
// request-derived is the file *contents*, or a value the read callback
// happens to close over — neither can escape a directory.
const fs = require('fs');
const path = require('path');

const AUDIT_LOG = '/var/log/app/audit.log';
const configCache = {};

// The headline case: constant path, tainted contents. Before the family was
// pinned to argument 0 this reported a path traversal because `note` is
// tainted, even though the destination is fixed.
function appendAudit(req, res) {
  const note = req.body.note;
  fs.writeFile(AUDIT_LOG, note, () => res.sendStatus(204));
}

function appendAuditSync(req) {
  fs.writeFileSync(AUDIT_LOG, req.body.note);
}

function exportRows(req) {
  const stream = fs.createWriteStream('/var/spool/app/export.csv');
  stream.write(req.body.rows);
  stream.end();
}

// The callback's *body* touches tainted data. Matching any argument meant
// the callback subtree alone made every fs.readFile fire.
function warmConfigCache(req) {
  const label = req.query.label;
  fs.readFile('config/app.json', 'utf8', (err, data) => {
    configCache[label] = data.length;
  });
}

function loadTemplate() {
  return fs.readFileSync('templates/mail.html', 'utf8');
}

function streamLogo(res) {
  fs.createReadStream('assets/logo.png').pipe(res);
}

function sendSummary(req, res) {
  res.sendFile('reports/summary.pdf', { root: '/srv/app' });
}

// path.join stays deliberately unindexed because every segment is a path
// component; with all-constant segments there is nothing tainted to report.
function publicIndex() {
  return path.join(__dirname, 'public', 'index.html');
}

module.exports = {
  appendAudit,
  appendAuditSync,
  exportRows,
  warmConfigCache,
  loadTemplate,
  streamLogo,
  sendSummary,
  publicIndex,
};
