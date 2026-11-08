using Microsoft.AspNetCore.Builder;

// ZS-CS-045: detailed errors for every environment.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseStaticFiles();
app.Run();
