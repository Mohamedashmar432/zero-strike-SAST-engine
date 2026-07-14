public class VulnCors
{
    public void Handle()
    {
        var origin = Request.QueryString["origin"];
        // ZS-CS-018: CORS misconfiguration — tainted origin reflected into Access-Control-Allow-Origin
        Response.AppendHeader("Access-Control-Allow-Origin", origin);
    }
}
