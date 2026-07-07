using System.Web;

public class AutocompleteHandler
{
    public void ProcessRequest(HttpContext context)
    {
        var term = context.Request.QueryString["term"];
        // ZS-CS-004: reflected XSS via a receiver-prefixed Response.Write call
        // (context.Response.Write, not the bare 2-segment Response.Write) —
        // exercises the callee_suffix dot-boundary match.
        context.Response.Write("[\"" + term + "\"]");
    }
}
