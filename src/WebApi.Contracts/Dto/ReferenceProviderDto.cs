namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One registered provider an admin can search and link a domain with (see <c>GET /api/reference-data/providers?type={type}</c>).
/// Only the multi-provider domains (books, video games) return any, the others an empty list.
/// </summary>
public class ReferenceProviderDto
{
    /// <summary>The provider's key ("googlebooks", "igdb"), passed back as <see cref="LinkReferenceRequestDto.Provider"/>.</summary>
    public required string Key { get; set; }

    /// <summary>Display name, such as "Google Books" or "IGDB".</summary>
    public required string DisplayName { get; set; }

    /// <summary>True for the domain's configured default, so a client preselects it rather than assuming the registration order.</summary>
    public required bool IsDefault { get; set; }
}
