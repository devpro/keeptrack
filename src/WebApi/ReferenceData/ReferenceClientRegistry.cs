namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves which provider client of a domain to use, by provider key or by falling back to the deployment
/// default (<c>ReferenceData:BookProvider</c>/<c>ReferenceData:VideoGameProvider</c>, passed in as
/// <paramref name="defaultProviderKey"/> - see Program.cs). One generic registry rather than one class per
/// domain: books and video games differ only in which interface they close over, and the domains that still
/// have exactly one client (TMDB/Discogs) inject it directly with no registry at all.
/// <para>
/// Depends on just the one string it needs rather than the whole <see cref="AppConfiguration"/>, so a unit
/// test can construct one without an unrelated config section (JWT/TMDB/Discogs settings) tripping
/// <see cref="AppConfiguration"/>'s own eager parsing.
/// </para>
/// </summary>
public class ReferenceClientRegistry<TClient>(IEnumerable<TClient> clients, string defaultProviderKey)
    where TClient : class, IReferenceProviderClient
{
    /// <summary>Every registered provider for this domain, in DI registration order.</summary>
    public IReadOnlyList<TClient> All { get; } = clients.ToList();

    /// <summary>
    /// <paramref name="providerKey"/> is matched case-insensitively so an existing deployment's setting
    /// (historically the PascalCase switch-case label, e.g. "OpenLibrary") keeps resolving against the
    /// lowercase <see cref="IReferenceProviderClient.ProviderKey"/> convention ("openlibrary") with no config
    /// migration needed.
    /// </summary>
    public TClient Resolve(string? providerKey)
    {
        var key = string.IsNullOrWhiteSpace(providerKey) ? defaultProviderKey : providerKey;
        return All.FirstOrDefault(c => string.Equals(c.ProviderKey, key, StringComparison.OrdinalIgnoreCase))
               ?? throw new ArgumentException($"Unknown provider '{key}'.", nameof(providerKey));
    }
}
