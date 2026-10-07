// True negatives for the ZS-JS-120..140 family.
const express = require('express');
const app = express();
app.get('/a', async (req, res) => {
  try {
    await work();
    res.cookie('session_id', 'x', { httpOnly: true, secure: true, sameSite: 'lax' });
    res.setHeader('Set-Cookie', 'sid=1; Secure; HttpOnly; SameSite=Lax');
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'internal error' });
  }
  res.download('/srv/static/report.pdf');
  res.redirect('/home');
});
