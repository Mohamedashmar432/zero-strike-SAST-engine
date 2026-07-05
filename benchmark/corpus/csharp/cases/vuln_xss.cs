public class GreetingPage
{
    public void Render()
    {
        var name = Request.QueryString["name"];
        Response.Write("<h1>Hello " + name + "</h1>"); // ZS-CS-004: reflected XSS
    }
}
