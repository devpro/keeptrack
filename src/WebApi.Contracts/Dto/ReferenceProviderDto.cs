namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One registered reference provider an admin can search/link a given domain with - see
/// <c>GET /api/reference-data/providers?type={type}</c>. Only the domains with more than one provider
/// (books, video games) return anything; the single-provider ones return an empty list.
/// </summary>
public class ReferenceProviderDto
{
    /// <summary>The provider's key, e.g. "googlebooks"/"igdb" - pass back as <see cref="LinkReferenceRequestDto.Provider"/>.</summary>
    public required string Key { get; set; }

    /// <summary>Human-readable name for display, e.g. "Google Books"/"IGDB".</summary>
    public required string DisplayName { get; set; }

    /// <summary>True for the domain's deployment-configured default provider, so a client can preselect it instead of assuming registration order.</summary>
    public required bool IsDefault { get; set; }
}
