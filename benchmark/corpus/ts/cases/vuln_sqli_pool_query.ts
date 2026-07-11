// ZS-TS-006: SQL injection via node-postgres/mysql2 pool — query built from req.query
const id: string = req.query.id;
pool.query("SELECT * FROM users WHERE id = " + id);
