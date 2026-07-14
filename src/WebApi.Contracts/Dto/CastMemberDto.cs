namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One cast credit, fully hydrated server-side (joined against the person reference collection) so
/// the client never needs a follow-up lookup per cast member.
/// </summary>
public class CastMemberDto
{
    public required string Name { get; set; }

    public required string CharacterName { get; set; }

    public string? ProfileImageUrl { get; set; }
}
