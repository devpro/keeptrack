namespace KeepTrack.WebApi.Configuration;

public class JwtBearerSettings
{
    public string Authority { get; set; } = string.Empty;

    public TokenValidationSettings TokenValidation { get; set; } = new TokenValidationSettings();
}
