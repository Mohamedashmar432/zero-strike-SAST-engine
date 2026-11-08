using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using NotesApi.Services;

namespace NotesApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ToolsController : ControllerBase
{
    private readonly ShellRunner _shell;

    public ToolsController(ShellRunner shell) => _shell = shell;

    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        var p = Process.Start("cmd.exe", "/c ping -n 1 " + host);
        p!.WaitForExit();
        return Ok();
    }

    [HttpGet("ping-safe")]
    public IActionResult PingSafe([FromQuery] string host)
    {
        var psi = new ProcessStartInfo("ping") { RedirectStandardOutput = true };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("1");
        psi.ArgumentList.Add(host);
        using var p = Process.Start(psi)!;
        return Ok(p.StandardOutput.ReadToEnd());
    }

    [HttpGet("health")]
    public IActionResult Health() => Ok(_shell.Uptime() + _shell.DiskFree());

    [HttpPost("import-binary")]
    public IActionResult ImportBinary([FromBody] byte[] payload)
    {
        using var ms = new MemoryStream(payload);
        var obj = new BinaryFormatter().Deserialize(ms);
        return Ok(obj.ToString());
    }

    [HttpPost("import-json")]
    public IActionResult ImportJson([FromBody] string json)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var obj = JsonConvert.DeserializeObject(json, settings);
        return Ok(obj);
    }

    [HttpPost("import-json-safe")]
    public IActionResult ImportJsonSafe([FromBody] string json)
    {
        var obj = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
        return Ok(obj);
    }

    [HttpPost("import-xml")]
    public IActionResult ImportXml([FromBody] string xml)
    {
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.LoadXml(xml);
        return Ok(doc.DocumentElement?.Name);
    }

    [HttpPost("import-xml-safe")]
    public IActionResult ImportXmlSafe([FromBody] string xml)
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        return Ok(doc.DocumentElement?.Name);
    }
}
