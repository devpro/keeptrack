namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// An admin's manual choice: link every tenant's unlinked (title, year) match to this provider id, and for an album only those by <see cref="Creator"/>.
/// </summary>
public class LinkReferenceRequestDto
{
    public required ReferenceItemType Type { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public required string ExternalId { get; set; }

    /// <summary>
    /// Which registered provider <see cref="ExternalId"/> came from, for the multi-provider domains (books, video games).
    /// Null means the domain's default provider.
    /// </summary>
    public string? Provider { get; set; }

    /// <summary>
    /// The ISBN the search used to find this candidate, books only.
    /// Carried from the search, so a stored alias records only an ISBN that drove the match, never the provider's own.
    /// </summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// The album's artist, required for an album since title and artist are its identity, ignored for every other type.
    /// </summary>
    public string? Creator { get; set; }
}
