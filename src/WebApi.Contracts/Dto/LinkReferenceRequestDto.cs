namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// An admin's manual choice: link every tenant's (Title, Year) match to this external provider id
/// (TMDB, Open Library, RAWG or Discogs, depending on <see cref="Type"/>).
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
}
