// Negative fixture for the path-traversal rule family (ZS-TS-022/023/030/
// 060/061/062/063/089). Every filesystem path below is a constant. What is
// request-derived is the file *contents*, or a value the read callback
// happens to close over — neither can escape a directory.
import * as fs from 'fs';
import * as path from 'path';

const AUDIT_LOG = '/var/log/app/audit.log';
const configCache: Record<string, number> = {};

// The headline case: constant path, tainted contents. Before the family was
// pinned to argument 0 this reported a path traversal because `note` is
// tainted, even though the destination is fixed.
export function appendAudit(req: any, res: any): void {
  const note: string = req.body.note;
  fs.writeFile(AUDIT_LOG, note, () => res.sendStatus(204));
}

export function appendAuditSync(req: any): void {
  fs.writeFileSync(AUDIT_LOG, req.body.note);
}

export function exportRows(req: any): void {
  const stream = fs.createWriteStream('/var/spool/app/export.csv');
  stream.write(req.body.rows);
  stream.end();
}

// The callback's *body* touches tainted data. Matching any argument meant
// the callback subtree alone made every fs.readFile fire.
export function warmConfigCache(req: any): void {
  const label: string = req.query.label;
  fs.readFile('config/app.json', 'utf8', (err, data) => {
    configCache[label] = data.length;
  });
}

export function loadTemplate(): string {
  return fs.readFileSync('templates/mail.html', 'utf8');
}

export function streamLogo(res: any): void {
  fs.createReadStream('assets/logo.png').pipe(res);
}

export function sendSummary(req: any, res: any): void {
  res.sendFile('reports/summary.pdf', { root: '/srv/app' });
}

// path.join stays deliberately unindexed because every segment is a path
// component; with all-constant segments there is nothing tainted to report.
export function publicIndex(): string {
  return path.join(__dirname, 'public', 'index.html');
}
