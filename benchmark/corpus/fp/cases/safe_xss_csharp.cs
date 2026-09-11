// Safe response writes. Nothing here should be reported.
//
// HttpResponse.Write has a Write(char[] buffer, int index, int count)
// overload. Only the buffer at argument 0 carries bytes into the response;
// `index` and `count` are offsets into markup the caller already holds, so a
// request-derived offset cannot introduce script. Before ZS-CS-004 was pinned
// to index 0 this was reported as reflected XSS.

public class BannerPage
{
    private static readonly char[] Banner = "<b>Welcome back</b>".ToCharArray();

    public void Render()
    {
        var offset = int.Parse(Request.QueryString["offset"]);
        Response.Write(Banner, offset, 8);
    }

    // The encoded form of the classic reflected-XSS shape: the value reaching
    // argument 0 has been HTML-encoded, so it is markup-safe by construction.
    public void RenderGreeting()
    {
        var safeName = HttpUtility.HtmlEncode(Request.QueryString["name"]);
        Response.Write(safeName);
    }
}
