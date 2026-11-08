using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

// ZS-CS-016, ZS-CS-027 and ZS-CS-043 look-alike: the host is fixed and only an
// escaped id varies.
[ApiController]
[Route("api/[controller]")]
public class RatesController : ControllerBase
{
    private static readonly HttpClient Client = new HttpClient();

    [HttpGet("rates")]
    public async Task<IActionResult> Rates([FromQuery] string currency)
    {
        var body = await Client.GetStringAsync("https://api.example.com/v1/rates/" + Uri.EscapeDataString(currency));
        var json = new WebClient().DownloadString("https://api.example.com/rates/" + Uri.EscapeDataString(currency));
        var req = (HttpWebRequest)WebRequest.Create("https://api.example.com/hook/" + Uri.EscapeDataString(currency));
        return Ok(body.Length + json.Length + req.Method.Length);
    }
}
