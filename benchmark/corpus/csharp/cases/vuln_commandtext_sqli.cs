using System.Data;
using System.Data.SQLite;

public class UserRepository
{
    public void LoadUser(SQLiteConnection connection)
    {
        var name = Request.QueryString["name"];
        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + name + "'"; // ZS-CS-012: SQL injection
        cmd.ExecuteReader();
    }
}
