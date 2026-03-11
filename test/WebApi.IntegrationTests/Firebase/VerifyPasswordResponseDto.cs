namespace Keeptrack.WebApi.IntegrationTests.Firebase;

public class VerifyPasswordResponseDto
{
    public required string Kind { get; init; }

    public required string LocalId { get; init; }

    public required string Email { get; init; }

    public string? DisplayName { get; init; }

    public required string IdToken { get; init; }

    public bool Registered { get; init; }

    public required string RefreshToken { get; init; }

    public required string ExpiresIn { get; init; }
}
