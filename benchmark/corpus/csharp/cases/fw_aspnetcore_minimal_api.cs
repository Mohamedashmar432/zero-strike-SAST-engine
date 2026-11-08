using Microsoft.AspNetCore.Builder;
using System.Diagnostics;

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/run", (string cmd) =>
{
    Process.Start(cmd); // ZS-CS-001: command injection
    return "started";
});

app.Run();
