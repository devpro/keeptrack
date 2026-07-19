namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One registered book reference provider an admin can search/link with - see
/// <c>GET /api/reference-data/book-providers</c>.
/// </summary>
public class BookProviderDto
{
    /// <summary>The provider's key, e.g. "openlibrary"/"bnf" - pass back as <see cref="LinkReferenceRequestDto.Provider"/>.</summary>
    public required string Key { get; set; }

    /// <summary>Human-readable name for display, e.g. "Open Library"/"BnF".</summary>
    public required string DisplayName { get; set; }
}
