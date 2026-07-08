public class CorsMiddleware
{
    public void Invoke(HttpResponse response)
    {
        response.Headers.Add("Access-Control-Allow-Origin", "*");
    }
}
