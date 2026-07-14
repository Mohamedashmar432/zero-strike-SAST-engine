// ZS-TS-021: Math.random() used to generate a value that should be unpredictable
const sessionToken: string = Math.random().toString(36);
