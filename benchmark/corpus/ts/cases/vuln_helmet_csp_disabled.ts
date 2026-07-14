// ZS-TS-020: helmet({ contentSecurityPolicy: false }) disables CSP
import helmet from 'helmet';
import express from 'express';
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
