namespace KeepTrack.BlazorApp.Configuration;

public class FirebaseClientSettings
{
    public required string ApiKey { get; init; }

    public required string AuthDomain { get; init; }

    public required string ProjectId { get; init; }
}
