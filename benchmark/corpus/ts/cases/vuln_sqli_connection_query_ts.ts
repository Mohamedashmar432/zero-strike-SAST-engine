// ZS-TS-056: SQL injection — connection.query() with tainted string
function findUser(req: any, connection: any) {
  const query = 'SELECT * FROM users WHERE id = ' + req.query.id;
  connection.query(query);
}
