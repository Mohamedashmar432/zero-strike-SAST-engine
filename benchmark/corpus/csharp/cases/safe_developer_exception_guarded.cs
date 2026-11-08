using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;

// ZS-CS-045 look-alike: only in Development.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
}
app.UseStaticFiles();
app.Run();
