using Microsoft.AspNetCore.Mvc;

namespace NotesApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ProxyController : ControllerBase
{
    private static readonly HttpClient Client = new();
    private static readonly HashSet<string> AllowedHosts = new() { "api.example.com", "cdn.example.com" };

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        var body = await Client.GetStringAsync(url);
        return Content(body);
    }

    [HttpPost("notify")]
    public async Task<IActionResult> Notify([FromBody] NotifyRequest req)
    {
        var response = await Client.PostAsync(req.CallbackUrl, new StringContent("{\"status\":\"done\"}"));
        return StatusCode((int)response.StatusCode);
    }

    [HttpGet("rates")]
    public async Task<IActionResult> Rates([FromQuery] string currency)
    {
        var body = await Client.GetStringAsync("https://api.example.com/v1/rates/" + Uri.EscapeDataString(currency));
        return Content(body);
    }

    [HttpGet("fetch-allowed")]
    public async Task<IActionResult> FetchAllowed([FromQuery] string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !AllowedHosts.Contains(uri.Host) || uri.Scheme != "https")
        {
            return BadRequest();
        }
        var body = await Client.GetStringAsync(uri);
        return Content(body);
    }
}

public record NotifyRequest(string CallbackUrl);
