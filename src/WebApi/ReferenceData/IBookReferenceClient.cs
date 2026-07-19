namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One book search hit - title, year, author and cover, enough for automatic matching or for an admin to
/// pick from when a match is ambiguous.
/// </summary>
public record BookSearchResult(string ExternalId, string Title, int? Year, string? Author, string? ImageUrl);

public record BookDetails(string ExternalId, string Title, int? Year, string? Synopsis, string? Author, string? AuthorExternalId, List<string> Genres, string? ImageUrl, string? Language = null, string? Isbn = null);

/// <summary>
/// Provider-agnostic book lookup, backing <see cref="ReferenceEnrichmentService"/>'s book resolution/refresh
/// and <see cref="ReferenceDataAdminController"/>'s admin search. Which concrete implementation is active is
/// a deployment-time choice (<c>ReferenceData:BookProvider</c>, see <c>Program.cs</c>) - nothing outside the
/// implementation itself (see <see cref="ProviderKey"/>) should assume which provider is behind this
/// interface. Interface exists so tests use a fake - never call a real provider's API from a test.
/// </summary>
public interface IBookReferenceClient
{
    /// <summary>
    /// The key this implementation's ids are stored under in <c>BookReferenceModel.ExternalIds</c> and in
    /// person/author-reference lookups (e.g. "openlibrary") - same role as the literal "tmdb"/"rawg"/
    /// "discogs" strings the single-provider domains use directly, just not hardcodable in the shared
    /// enrichment service here since more than one implementation of this interface can exist. Each
    /// implementation owns its own key; callers must never hardcode a provider name.
    /// </summary>
    string ProviderKey { get; }

    /// <summary>
    /// Human-readable name shown to an admin choosing a provider (e.g. "Open Library", "BnF") - the single
    /// source of truth for that text, instead of a per-<see cref="ReferenceItemType"/> switch hardcoding it
    /// (fine for the single-provider domains, but Book now has more than one).
    /// </summary>
    string DisplayName { get; }

    /// <summary>
    /// <paramref name="author"/> narrows the query when known - without it, a common title can return
    /// dozens of unrelated results. <paramref name="year"/> is an optional hint; whether and how an
    /// implementation uses it server-side is provider-specific (see e.g. <see cref="OpenLibraryClient"/>'s
    /// own reasoning for why it never filters by year). It is still returned per candidate for the
    /// caller/admin to use when picking. <paramref name="isbn"/>, when supplied, is an exact identifier -
    /// currently only <see cref="GoogleBooksClient"/> actually uses it (as the sole query, superseding
    /// title/author entirely, since an ISBN uniquely identifies an edition); other implementations accept
    /// but ignore it rather than needing a separate interface per provider.
    /// </summary>
    Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default);

    Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
