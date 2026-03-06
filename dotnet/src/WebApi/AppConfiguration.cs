using KeepTrack.WebApi.Configuration;
using Withywoods.Configuration;

namespace KeepTrack.WebApi;

public class AppConfiguration(IConfiguration configuration)
{
    public static string CorsPolicyName => "CorsPolicyName";

    public static string HealthCheckEndpoint => "/health";

    public bool IsHttpsRedirectionEnabled => configuration.TryGetSection<bool>("Features:IsHttpsRedirectionEnabled");

    public bool IsScalarEnabled => configuration.TryGetSection<bool>("Features:IsScalarEnabled");

    public OpenApiInfo OpenApiInfo => configuration.TryGetSection<OpenApiInfo>("OpenApi");

    public JwtBearerSettings JwtBearerSettings = configuration.TryGetSection<JwtBearerSettings>("Authentication:JwtBearer");

    public string ConnectionString => configuration.TryGetSection<string>("Infrastructure:MongoDB:ConnectionString");

    public string DatabaseName => configuration.TryGetSection<string>("Infrastructure:MongoDB:DatabaseName");

    /// <summary>
    /// Allowed Origin URL for Cross-Origin Requests (CORS)
    /// </summary>
    /// <remarks>
    /// See https://docs.microsoft.com/en-us/aspnet/core/security/cors
    /// </remarks>
    public List<string> CorsAllowedOrigin => configuration.TryGetSection<List<string>>("AllowedOrigins");
}
