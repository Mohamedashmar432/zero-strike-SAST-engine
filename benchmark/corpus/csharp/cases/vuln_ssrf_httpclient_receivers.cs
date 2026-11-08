using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

// ZS-CS-016, ZS-CS-027 and ZS-CS-043: request URLs fetched through HttpClient
// verbs on a field named Client, WebClient created inline, and WebRequest.
[ApiController]
[Route("api/[controller]")]
public class ProxyController : ControllerBase
{
    private static readonly HttpClient Client = new HttpClient();

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        var body = await Client.GetStringAsync(url);
        return Content(body);
    }

    [HttpGet("preview")]
    public IActionResult Preview([FromQuery] string url)
    {
        var html = new WebClient().DownloadString(url);
        return Content(html);
    }

    [HttpPost("notify")]
    public IActionResult Notify([FromQuery] string callbackUrl)
    {
        var req = (HttpWebRequest)WebRequest.Create(callbackUrl);
        return Ok(req.Method);
    }
}
