using System.Data;
using System.Data.SQLite;

// Mirrors the real-world safe pattern found in WebGoat.NET's
// SQLiteMembershipProvider.cs: table/column names are constants
// concatenated into the query text, but the actual user-controlled value
// is always bound through a parameter, never spliced into the string.
// ZS-CS-012 must NOT fire here.
public class UserRepository
{
    private const string USER_TB_NAME = "aspnet_Users";

    public void UpdateLastActivity(SQLiteConnection connection, string username)
    {
        var cmd = connection.CreateCommand();
        cmd.CommandText = "UPDATE " + USER_TB_NAME + " SET LastActivityDate = $LastActivityDate WHERE LoweredUsername = $Username";
        cmd.Parameters.AddWithValue("$LastActivityDate", System.DateTime.UtcNow);
        cmd.Parameters.AddWithValue("$Username", username.ToLowerInvariant());
        cmd.ExecuteNonQuery();
    }
}
