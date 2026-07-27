// ZS-JS-058: SQL injection via mysql/mysql2 connection — query built from req.query
const id = req.query.id;
connection.query("SELECT * FROM users WHERE id = " + id);
