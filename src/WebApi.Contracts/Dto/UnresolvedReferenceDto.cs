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
}
