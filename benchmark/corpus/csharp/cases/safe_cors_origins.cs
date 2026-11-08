using Microsoft.Extensions.DependencyInjection;

// ZS-CS-041 look-alike: an explicit origin list.
public static class CorsSetupSafe
{
    public static void Configure(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("Trusted", policy => policy.WithOrigins("https://app.example.com").AllowAnyHeader().AllowAnyMethod());
        });
    }
}
