using System.Data.SqlClient;

public class UserRepository
{
    public void LoadUser(SqlConnection connection)
    {
        var name = Request.QueryString["name"];
        var query = "SELECT * FROM Users WHERE Name = '" + name + "'";
        var command = new SqlCommand(query, connection); // ZS-CS-002: SQL injection
        command.ExecuteReader();
    }
}
