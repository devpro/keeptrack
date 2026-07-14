namespace Keeptrack.Domain.Models;

/// <summary>
/// One (title, year) combination ever confirmed - via TMDB resolution, automatic or admin-picked - to mean
/// a specific show/movie, embedded within a <see cref="TvShowReferenceModel"/>/<see cref="MovieReferenceModel"/>.
/// See <see cref="TvShowReferenceModel.MatchedAliases"/> for the full rationale: a title-only match isn't
/// enough because two tenants (or a tenant and TMDB's own canonical data) can legitimately record different
/// years for the exact same show/movie, so year has to travel with the specific title variant it was
/// confirmed under, not live as a single scalar on the reference document.
/// </summary>
public class ReferenceMatchModel
{
    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>
    /// Normalized book author / album artist this (title, year) combination was confirmed under - null
    /// for domains with no creator concept (TV show, movie, video game). Required for Book/Album matching
    /// specifically: two different tenants' different books/albums can easily share a common (title, year)
    /// (e.g. two different novels both titled "Echoes" published the same year) - without creator in the
    /// match key, the second tenant's item would incorrectly latch onto the first tenant's reference
    /// document. Deliberately generic name, not "Author"/"Artist" - see <see cref="TvShowReferenceModel.MatchedAliases"/>'s
    /// own naming rationale, which this follows.
    /// </summary>
    public string? Creator { get; set; }
}
