namespace Keeptrack.WebApi.Authentication;

public class JwtBearerSettings
{
    public required string Authority { get; set; }

    public required TokenValidationSettings TokenValidation { get; set; }
}
