namespace Keeptrack.Domain.Models;

/// <summary>
/// One track's reference metadata (position, title, duration), embedded in an <see cref="AlbumReferenceModel"/> like <see cref="ReferenceEpisodeModel"/>:
/// bounded by the real tracklist and always fetched whole.
/// </summary>
public class ReferenceTrackModel
{
    /// <summary>
    /// Discogs' position label, not always numeric: vinyl releases use side and track, like "A1" or "B2".
    /// </summary>
    public required string Position { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// Discogs' "M:SS" text, often absent, kept as display text rather than parsed.
    /// </summary>
    public string? Duration { get; set; }
}
