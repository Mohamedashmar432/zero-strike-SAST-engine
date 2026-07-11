// ZS-JS-022: SQL injection via node-postgres/mysql2 client — query built from req.query
const id = req.query.id;
client.query("SELECT * FROM users WHERE id = " + id);
