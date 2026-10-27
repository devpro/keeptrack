namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded in <see cref="AlbumReference"/> (see <see cref="Keeptrack.Domain.Models.ReferenceTrackModel"/> for why).
/// </summary>
public class ReferenceTrack
{
    public required string Position { get; set; }

    public required string Title { get; set; }

    public string? Duration { get; set; }
}
