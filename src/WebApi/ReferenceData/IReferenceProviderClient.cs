namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// What every external reference provider client has in common, whichever domain it serves: a key its ids are
/// stored under and a name an admin sees. Exists so <see cref="ReferenceClientRegistry{TClient}"/> can be
/// written once for every multi-provider domain rather than copied per domain (Book had the only registry
/// until video games gained a second provider).
/// </summary>
public interface IReferenceProviderClient
{
    /// <summary>
    /// The key this implementation's ids are stored under in a reference document's <c>ExternalIds</c> and in
    /// person-reference lookups (e.g. "googlebooks", "igdb") - the same role the literal "tmdb"/"discogs"
    /// strings play in the single-provider domains, just not hardcodable where more than one implementation
    /// can exist. Each implementation owns its own key; callers must never hardcode a provider name.
    /// </summary>
    string ProviderKey { get; }

    /// <summary>
    /// Human-readable name shown to an admin choosing a provider (e.g. "Google Books", "IGDB") - the single
    /// source of truth for that text, instead of a per-<see cref="ReferenceItemType"/> switch hardcoding it.
    /// </summary>
    string DisplayName { get; }
}
