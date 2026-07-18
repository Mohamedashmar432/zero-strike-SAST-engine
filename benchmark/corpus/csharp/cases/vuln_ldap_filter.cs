using System.DirectoryServices;

public class UserDirectory
{
    public void FindUser()
    {
        var uid = Request.QueryString["uid"];
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + uid + ")"; // ZS-CS-024: LDAP injection
        searcher.FindOne();
    }
}
