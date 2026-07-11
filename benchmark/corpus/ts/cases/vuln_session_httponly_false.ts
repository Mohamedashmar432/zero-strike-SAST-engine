import session from 'express-session';
import express from 'express';
const app = express();

app.use(session({
  secret: 'keyboard cat',
  cookie: { httpOnly: false }
}));
