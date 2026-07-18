using System.Net;

public class PreviewFetcher
{
    public string Fetch()
    {
        var url = Request.QueryString["url"];
        var client = new WebClient();
        return client.DownloadString(url); // ZS-CS-027: SSRF
    }
}
