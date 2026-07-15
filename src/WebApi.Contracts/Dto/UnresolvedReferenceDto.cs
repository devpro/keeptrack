namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A distinct (title, year) pair, across all tenants, that has no reference-data link yet - one entry
/// in the admin curation queue at GET /api/reference-data/unresolved.
/// </summary>
public class UnresolvedReferenceDto
{
    public required ReferenceItemType Type { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>
    /// A creator (book author / album artist) taken from one of the unresolved tenant items sharing this
    /// (title, year) pair - a search-prefill convenience only, null for types with no creator dimension.
    /// </summary>
    public string? Creator { get; set; }
}
