const express = require('express');
const session = require('express-session');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const swig = require('swig');

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true }
}));

const verifyOptions: Record<string, unknown> = { algorithms: ['HS256'], ignoreExpiration: false };
const check = (token: string) => jwt.verify(token, process.env.JWT_SECRET, verifyOptions);

swig.setDefaults({ autoescape: true });

app.use(cors({ origin: ['https://app.example.test'], credentials: true }));
app.use(cors({ origin: true }));

module.exports = { app, check };
