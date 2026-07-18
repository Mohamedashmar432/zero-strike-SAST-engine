using System.Xml;

public class AccountLookup
{
    public void Find()
    {
        var login = Request.QueryString["login"];
        var doc = new XmlDocument();
        var nodes = doc.SelectNodes("//user[login='" + login + "']"); // ZS-CS-025: XPath injection
    }
}
