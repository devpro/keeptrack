namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves a domain's provider client by key,
/// or else the default (<c>ReferenceData:BookProvider</c>, <c>ReferenceData:VideoGameProvider</c>), passed as <paramref name="defaultProviderKey"/>.
/// One generic registry, since books and video games differ only in their interface, and the single-client domains (TMDB, Discogs) inject their client directly.
/// <para>
/// It takes the one string it needs rather than <see cref="AppConfiguration"/>, so a unit test builds one without unrelated configuration sections.
/// </para>
/// </summary>
public class ReferenceClientRegistry<TClient>(IEnumerable<TClient> clients, string defaultProviderKey)
    where TClient : class, IReferenceProviderClient
{
    /// <summary>Every registered provider for this domain, in DI registration order.</summary>
    public IReadOnlyList<TClient> All { get; } = clients.ToList();

    /// <summary>The default provider's key, not necessarily the first of <see cref="All"/>.</summary>
    public string DefaultProviderKey { get; } = defaultProviderKey;

    /// <summary>
    /// <paramref name="providerKey"/> is matched case-insensitively,
    /// so a setting such as "OpenLibrary" resolves to the lowercase <see cref="IReferenceProviderClient.ProviderKey"/> "openlibrary".
    /// </summary>
    public TClient Resolve(string? providerKey)
    {
        var key = string.IsNullOrWhiteSpace(providerKey) ? DefaultProviderKey : providerKey;
        return All.FirstOrDefault(c => string.Equals(c.ProviderKey, key, StringComparison.OrdinalIgnoreCase))
               ?? throw new ArgumentException($"Unknown provider '{key}'.", nameof(providerKey));
    }
}
