namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One track's reference metadata (position, title, duration) from the shared reference collection.
/// </summary>
public class ReferenceTrackDto
{
    public required string Position { get; set; }

    public required string Title { get; set; }

    public string? Duration { get; set; }
}
