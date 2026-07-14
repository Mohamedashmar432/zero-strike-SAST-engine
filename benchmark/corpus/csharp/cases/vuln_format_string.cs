public class VulnFormatString
{
    public string Greet()
    {
        var username = Request.QueryString["username"];
        // ZS-CS-019: tainted format string — string.Format() called with a tainted argument
        return string.Format("User: {0}", username);
    }
}
