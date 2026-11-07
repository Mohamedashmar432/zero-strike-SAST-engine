using System.Net.Http;
using System.Threading.Tasks;

public class HostFetcher
{
    private readonly HttpClient httpClient = new HttpClient();

    public async Task<string> FetchAsync()
    {
        var host = Request.QueryString["host"];
        var response = await httpClient.GetAsync($"https://{host}/status"); // ZS-CS-016: SSRF
        return await response.Content.ReadAsStringAsync();
    }
}
