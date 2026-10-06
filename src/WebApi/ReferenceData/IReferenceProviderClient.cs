namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// What every provider client shares, whatever its domain: a key its ids are stored under and a name an admin sees.
/// It lets <see cref="ReferenceClientRegistry{TClient}"/> be written once for every multi-provider domain.
/// </summary>
public interface IReferenceProviderClient
{
    /// <summary>
    /// The key this provider's ids are stored under in a reference's <c>ExternalIds</c> and in person lookups ("googlebooks", "igdb"), as "tmdb" is in a single-provider domain.
    /// Each implementation owns its key, and callers never hardcode a provider name.
    /// </summary>
    string ProviderKey { get; }

    /// <summary>
    /// The name shown to an admin choosing a provider ("Google Books", "IGDB"), declared only here.
    /// </summary>
    string DisplayName { get; }
}
