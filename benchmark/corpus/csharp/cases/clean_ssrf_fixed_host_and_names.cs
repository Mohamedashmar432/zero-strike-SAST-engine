using System.Net.Http;
using System.Threading.Tasks;

public class CatalogClient
{
    private readonly HttpClient httpClient = new HttpClient();
    private const string PasswordFieldName = "Password";
    private const string TokenEndpoint = "/connect/token";
    private const string PasswordError = "Invalid user name or password";

    public async Task<string> GetItemAsync()
    {
        var id = Request.QueryString["id"];
        var a = await httpClient.GetAsync($"https://api.service.invalid/items/{id}");
        var b = await httpClient.GetAsync("https://api.service.invalid/items/" + id);
        var c = await httpClient.GetAsync($"{baseUrl}/items/{id}");
        return await a.Content.ReadAsStringAsync();
    }

    public async Task<string> FetchAsync(string url)
    {
        var response = await httpClient.GetAsync(url);
        return await response.Content.ReadAsStringAsync();
    }

    public string Log(string format, object arg)
    {
        return string.Format(format, arg);
    }
}
