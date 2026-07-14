namespace Keeptrack.Domain.Models;

/// <summary>
/// One track's reference metadata (position, title, duration), embedded within an
/// <see cref="AlbumReferenceModel"/> - same embedding rationale as
/// <see cref="ReferenceEpisodeModel"/>: bounded to one album's real tracklist and always fetched as a whole.
/// </summary>
public class ReferenceTrackModel
{
    /// <summary>
    /// Discogs' own position label - not always numeric (vinyl releases use side+track like "A1"/"B2").
    /// </summary>
    public required string Position { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// Discogs' own "M:SS" text, often absent - carried through as display text, not parsed.
    /// </summary>
    public string? Duration { get; set; }
}
