using MySql.Data.MySqlClient;

public class UserRepository
{
    public void LoadUser(MySqlConnection connection)
    {
        var name = Request.QueryString["name"];
        var query = "SELECT * FROM Users WHERE Name = '" + name + "'";
        var command = new MySqlCommand(query, connection); // ZS-CS-007: SQL injection
        command.ExecuteReader();
    }
}
