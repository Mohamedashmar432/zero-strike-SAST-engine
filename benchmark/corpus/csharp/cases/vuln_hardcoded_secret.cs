public class DatabaseConfig
{
    public void Connect()
    {
        var password = "hunter2"; // ZS-CS-006: hardcoded credential
        var apiKey = "sk-1234567890abcdef"; // ZS-CS-006: hardcoded credential
        Login("admin", password, apiKey);
    }
}
