namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves which <see cref="IBookReferenceClient"/> to use, by provider key or by falling back to the
/// deployment default (<c>ReferenceData:BookProvider</c>, passed in as <paramref name="defaultProviderKey"/>
/// - see Program.cs). Exists because Book is the one reference domain with more than one registered
/// provider; every other domain (TMDB/RAWG/Discogs) still has exactly one client injected directly, with no
/// equivalent registry needed. Depends on just the one string it needs rather than the whole
/// <see cref="AppConfiguration"/>, so a unit test can construct one without an unrelated config section
/// (JWT/TMDB/RAWG/Discogs settings) tripping <see cref="AppConfiguration"/>'s own eager parsing.
/// </summary>
public class BookReferenceClientRegistry(IEnumerable<IBookReferenceClient> clients, string defaultProviderKey)
{
    /// <summary>Every registered book provider, in DI registration order.</summary>
    public IReadOnlyList<IBookReferenceClient> All { get; } = clients.ToList();

    /// <summary>
    /// <paramref name="providerKey"/> is matched case-insensitively so an existing deployment's
    /// <c>ReferenceData:BookProvider</c> setting (historically the PascalCase switch-case label, e.g.
    /// "OpenLibrary") keeps resolving against the lowercase <see cref="IBookReferenceClient.ProviderKey"/>
    /// convention ("openlibrary") with no config migration needed.
    /// </summary>
    public IBookReferenceClient Resolve(string? providerKey)
    {
        var key = providerKey ?? defaultProviderKey;
        return All.FirstOrDefault(c => string.Equals(c.ProviderKey, key, StringComparison.OrdinalIgnoreCase))
               ?? throw new ArgumentException($"Unknown book provider '{key}'.", nameof(providerKey));
    }
}
