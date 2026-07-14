// ZS-TS-015: SQL injection via Sequelize — query built from req.body
const login: string = req.body.login;
db.sequelize.query("SELECT * FROM users WHERE login='" + login + "'");
