using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using TicketDesk.Data;
using TicketDesk.Services;

const string IntegrationToken = "EXAMPLE-NOT-REAL-integration-token";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddHttpClient();
builder.Services.AddDbContext<DeskContext>(o => o.UseSqlite("Data Source=desk.db"));
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

var app = builder.Build();
app.UseDeveloperExceptionPage();
app.UseCors();
app.UseStaticFiles();
app.MapRazorPages();

var webhookSecret = Environment.GetEnvironmentVariable("WEBHOOK_SECRET");

app.MapGet("/api/tickets", (string reporter, SqliteConnection db) =>
{
    var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT Id, Title FROM Tickets WHERE Reporter = '" + reporter + "'";
    using var r = cmd.ExecuteReader();
    var rows = new List<string>();
    while (r.Read()) rows.Add(r.GetString(1));
    return Results.Ok(rows);
});

app.MapGet("/api/tickets/safe", (string reporter, SqliteConnection db) =>
{
    var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT Id, Title FROM Tickets WHERE Reporter = $reporter";
    cmd.Parameters.AddWithValue("$reporter", reporter);
    using var r = cmd.ExecuteReader();
    var rows = new List<string>();
    while (r.Read()) rows.Add(r.GetString(1));
    return Results.Ok(rows);
});

app.MapDelete("/api/tickets/by-status", (string status, DeskContext ctx) =>
{
    var n = ctx.Database.ExecuteSqlRaw("DELETE FROM Tickets WHERE Status = '" + status + "'");
    return Results.Ok(n);
});

app.MapDelete("/api/tickets/by-owner", (string owner, DeskContext ctx) =>
{
    var n = ctx.Database.ExecuteSqlInterpolated($"DELETE FROM Tickets WHERE Owner = {owner}");
    return Results.Ok(n);
});

app.MapGet("/api/attachments", (string name) =>
{
    var path = Path.Combine(AppContext.BaseDirectory, "attachments", name);
    return Results.File(File.ReadAllBytes(path), "application/octet-stream");
});

app.MapGet("/api/attachments/safe", (string name) =>
{
    var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "attachments"));
    var full = Path.GetFullPath(Path.Combine(root, Path.GetFileName(name)));
    if (!full.StartsWith(root)) return Results.BadRequest();
    return Results.File(File.ReadAllBytes(full), "application/octet-stream");
});

app.MapPost("/api/webhooks/test", async (WebhookTest req, HttpClient http) =>
{
    var res = await http.GetAsync(req.Url);
    return Results.Ok((int)res.StatusCode);
});

app.MapGet("/api/status/upstream", async (string component, HttpClient http) =>
{
    var res = await http.GetAsync("https://status.example.com/api/components/" + Uri.EscapeDataString(component));
    return Results.Ok((int)res.StatusCode);
});

app.MapGet("/go", (string to) => Results.Redirect(to));

app.MapGet("/go/safe", (string to) =>
{
    if (!to.StartsWith('/') || to.StartsWith("//")) to = "/";
    return Results.LocalRedirect(to);
});

app.MapPost("/api/git", (string args) =>
{
    var p = Process.Start("git", args);
    p!.WaitForExit();
    return Results.Ok();
});

app.MapGet("/api/git/status", () => Results.Ok(GitRunner.Run("status")));
app.MapGet("/api/git/log", () => Results.Ok(GitRunner.Run("log")));

app.MapPost("/api/session", (HttpContext ctx) =>
{
    var rng = new Random();
    var sid = rng.Next().ToString();
    ctx.Response.Cookies.Append("desk_sid", sid);
    return Results.Ok();
});

app.MapPost("/api/session/secure", (HttpContext ctx) =>
{
    var sid = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    ctx.Response.Cookies.Append("desk_sid", sid, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
    return Results.Ok();
});

app.MapPost("/api/import", (string payload) =>
{
    var obj = JsonConvert.DeserializeObject(payload, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto });
    return Results.Ok(obj);
});

app.MapPost("/api/import/safe", (string payload) =>
{
    var obj = JsonConvert.DeserializeObject<Dictionary<string, string>>(payload);
    return Results.Ok(obj);
});

app.MapPost("/api/password-hash", (string password) =>
{
    var sha = SHA1.HashData(Encoding.UTF8.GetBytes(password));
    return Results.Ok(Convert.ToHexString(sha));
});

app.MapPost("/api/password-hash/strong", (string password) =>
{
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 310000, HashAlgorithmName.SHA256, 32);
    return Results.Ok(Convert.ToHexString(hash));
});

app.MapPost("/api/encrypt", (string text) =>
{
    using var des = DES.Create();
    return Results.Ok(des.CreateEncryptor().TransformFinalBlock(Encoding.UTF8.GetBytes(text), 0, text.Length));
});

app.MapPost("/api/encrypt/strong", (string text) =>
{
    using var aes = Aes.Create();
    aes.KeySize = 256;
    return Results.Ok(aes.CreateEncryptor().TransformFinalBlock(Encoding.UTF8.GetBytes(text), 0, text.Length));
});

app.Run();

public record WebhookTest(string Url);
