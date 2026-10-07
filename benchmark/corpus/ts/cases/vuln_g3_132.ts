// ZS-TS-132: CWE-22: fs.promises write to a caller-chosen path
const fsPromise = require('fs').promises;
async function saveNote(req, res) {
  const filePath = './notes/' + req.body.name;
  await fsPromise.writeFile(filePath, req.body.text);
  res.json({ ok: true });
}
