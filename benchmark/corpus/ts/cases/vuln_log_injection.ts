// ZS-TS-081: log injection — request data logged without sanitizing newlines
const q = req.query.q;
console.log(q);
