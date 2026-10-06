namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One cast credit, hydrated server side from the person references, so the client needs no lookup per cast member.
/// </summary>
public class CastMemberDto
{
    public required string Name { get; set; }

    public required string CharacterName { get; set; }

    public string? ProfileImageUrl { get; set; }
}
