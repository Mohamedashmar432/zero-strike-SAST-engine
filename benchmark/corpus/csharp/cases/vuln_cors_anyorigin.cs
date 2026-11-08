using Microsoft.Extensions.DependencyInjection;

// ZS-CS-041: any origin may read responses.
public static class CorsSetup
{
    public static void Configure(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("Open", policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
        });
    }
}
