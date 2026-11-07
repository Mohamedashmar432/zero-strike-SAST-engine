// True negatives for the workstream F precision gates (all synthetic):
// requests to a fixed service that vary only an id or query, a request
// helper that takes its URL as a plain parameter, exec() with a constant
// command and a (error, stdout) callback, and a SQL wrapper that passes its
// own parameter straight through.
const axios = require('axios');
const { exec } = require('child_process');

const BASE_URL = 'https://api.service.invalid';

function getUser(req, res) {
  const id = req.params.id;
  axios.get(`https://api.service.invalid/users/${id}`);
  axios.get('https://api.service.invalid/users/' + req.query.id);
  axios.get(`${BASE_URL}/users/${id}`);
  axios.get(`${process.env.USER_API}/users/${id}`);
  const searchUrl = `https://api.service.invalid/search?q=${req.query.q}`;
  axios.get(searchUrl);
  axios.post('/internal/items/' + req.body.id, { ok: true });
}

function get(url) {
  return axios.get(url);
}

function listFiles() {
  exec('ls -l', (error, stdout, stderr) => {
    console.log(stdout);
  });
}

function runQuery(sql) {
  return db.sequelize.query(sql);
}
