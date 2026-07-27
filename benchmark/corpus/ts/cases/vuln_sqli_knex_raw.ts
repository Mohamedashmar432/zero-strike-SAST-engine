// ZS-TS-057: SQL injection via knex.raw() — fragment built from req.query
const id = req.query.id;
knex.raw("SELECT * FROM users WHERE id = " + id);
