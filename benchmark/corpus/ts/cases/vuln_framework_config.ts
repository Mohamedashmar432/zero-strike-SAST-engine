const express = require('express');
const session = require('express-session');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const swig = require('swig');

const app = express();

// signing secret written as a literal (ZS-JS-180)
app.use(session({ secret: 'synthetic-session-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: true } }));

// secure flag never set on the session cookie (ZS-JS-182): see the second call below
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));

const verifyOptions: Record<string, unknown> = { algorithms: ['HS256'], ignoreExpiration: true };
const check = (token: string) => jwt.verify(token, process.env.JWT_SECRET, verifyOptions);

swig.setDefaults({ autoescape: false });

app.use(cors({ origin: true, credentials: true }));

module.exports = { app, check };
