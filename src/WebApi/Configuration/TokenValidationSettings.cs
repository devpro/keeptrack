namespace Keeptrack.WebApi.Configuration;

public class TokenValidationSettings
{
    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;
}
