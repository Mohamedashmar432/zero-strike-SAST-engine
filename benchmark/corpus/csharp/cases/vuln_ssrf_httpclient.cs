using System.Net.Http;
using System.Threading.Tasks;

public class UrlFetcher
{
    private readonly HttpClient httpClient = new HttpClient();

    public async Task<string> FetchAsync()
    {
        var url = Request.QueryString["url"];
        var response = await httpClient.GetAsync(url); // ZS-CS-016: SSRF
        return await response.Content.ReadAsStringAsync();
    }
}
