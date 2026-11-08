using Microsoft.EntityFrameworkCore;
using NotesApi.Data;
using NotesApi.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews().AddNewtonsoftJson();
builder.Services.AddDbContext<NotesContext>(o =>
    o.UseSqlServer(builder.Configuration.GetConnectionString("Notes")));
builder.Services.AddSingleton<ShellRunner>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("Open", policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("Open");
app.UseAuthorization();
app.MapControllerRoute(name: "default", pattern: "{controller=Notes}/{action=Index}/{id?}");
app.Run();

public static class Secrets
{
    public const string JwtSigningKey = "EXAMPLE-NOT-REAL-signing-key-0000";
    public static string FromConfig(IConfiguration config) => config["Jwt:Key"]!;
}
