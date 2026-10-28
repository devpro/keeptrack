namespace Keeptrack.Common.Hosting.Authentication;

public class LocalTokenSettings
{
    public required string SigningKey { get; init; }

    public required string Issuer { get; init; }

    public required string Audience { get; init; }
}
