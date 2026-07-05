// ZS-TS-004: TLS certificate validation disabled
https.request(url, { rejectUnauthorized: false });
