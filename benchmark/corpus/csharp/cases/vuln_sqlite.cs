using System.Data;
using System.Data.SQLite;

public class UserRepository
{
    public void LoadUser(SQLiteConnection connection)
    {
        var email = Request.QueryString["email"];
        var sql = "SELECT * FROM Users WHERE Email = '" + email + "'";
        var da = new SqliteDataAdapter(sql, connection); // ZS-CS-011: SQL injection
        var ds = new DataSet();
        da.Fill(ds);
    }
}
