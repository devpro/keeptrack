namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded within <see cref="AlbumReference"/> - see that class for why embedding is the right call here.
/// </summary>
public class ReferenceTrack
{
    public required string Position { get; set; }

    public required string Title { get; set; }

    public string? Duration { get; set; }
}
