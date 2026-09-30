namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// An admin's manual choice: link every tenant's unlinked (Title, Year) match to this external provider id (TMDB, Open Library, RAWG or Discogs, depending on <see cref="Type"/>), and for an album only the ones by <see cref="Creator"/>.
/// </summary>
public class LinkReferenceRequestDto
{
    public required ReferenceItemType Type { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public required string ExternalId { get; set; }

    /// <summary>
    /// Which registered provider <see cref="ExternalId"/> came from - only meaningful for
    /// <see cref="ReferenceItemType.Book"/> (the one domain with more than one registered provider); null
    /// for every other type, and null here falls back to the deployment's default book provider.
    /// </summary>
    public string? Provider { get; set; }

    /// <summary>
    /// The ISBN actually used to find this candidate, when the preceding search used one - Book-only, null
    /// for every other type. Carried from the search step to this one so the stored match alias only ever
    /// records an ISBN that genuinely drove the match, never backfilled from the provider's own data.
    /// </summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// The album's artist, required for an album since title and artist are its identity, ignored for every other type.
    /// </summary>
    public string? Creator { get; set; }
}
