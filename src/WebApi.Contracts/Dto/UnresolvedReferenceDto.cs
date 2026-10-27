namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A distinct (title, year) pair, across all tenants, with no reference link yet: one entry of the admin queue at GET /api/reference-data/unresolved.
/// </summary>
public class UnresolvedReferenceDto
{
    public required ReferenceItemType Type { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>
    /// A creator (book author, album artist) from one of the unresolved items sharing this pair, only to prefill the search, null for the domains without a creator.
    /// </summary>
    public string? Creator { get; set; }

    /// <summary>
    /// A book's ISBN, when one of the unresolved items sharing this pair records one, only to prefill the search like <see cref="Creator"/>.
    /// </summary>
    public string? Isbn { get; set; }
}
