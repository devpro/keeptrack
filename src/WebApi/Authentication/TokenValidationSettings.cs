namespace Keeptrack.WebApi.Authentication;

public class TokenValidationSettings
{
    public required string Issuer { get; set; }

    public required string Audience { get; set; }
}
