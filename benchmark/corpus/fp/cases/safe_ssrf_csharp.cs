using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

// SSRF family negative fixture (ZS-CS-016).
//
// The request goes to a compile-time constant. What is attacker-controlled is
// the cancellation deadline at argument 1, which decides how long the call
// waits, not where it goes -- so it is not CWE-918.
//
// Before ZS-CS-016 was pinned to argument 0, "tainted_argument: true" was
// satisfied by any tainted identifier anywhere in the call's subtree, so this
// was reported as SSRF.
//
// ZS-CS-027 (client.DownloadString) has no case here: its only argument IS
// the destination, so there is no non-URL position to suppress.
public class AuditForwarder
{
    private const string AuditUrl = "https://audit.internal.example.com/v1/events";

    private readonly HttpClient httpClient = new HttpClient();

    public async Task<string> FetchAsync()
    {
        var seconds = double.Parse(Request.QueryString["timeout"]);
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        var response = await httpClient.GetAsync(AuditUrl, cts.Token);
        return await response.Content.ReadAsStringAsync();
    }
}
