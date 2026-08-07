public class VulnFormatString
{
    public string Greet()
    {
        var username = Request.QueryString["username"];
        // ZS-CS-019: the FORMAT STRING itself is attacker-controlled. The safe
        // string.Format("User: {0}", username) idiom must not fire — see clean.cs.
        return string.Format("User: " + username);
    }
}
