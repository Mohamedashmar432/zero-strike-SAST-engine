// ZS-JS-011: SQL injection via Sequelize — query built from req.body
const login = req.body.login;
db.sequelize.query("SELECT * FROM users WHERE login='" + login + "'");
