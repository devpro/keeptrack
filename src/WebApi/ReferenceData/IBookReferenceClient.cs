namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One book search hit - title, year, author and cover, enough for automatic matching or for an admin to
/// pick from when a match is ambiguous.
/// </summary>
public record BookSearchResult(string ExternalId, string Title, int? Year, string? Author, string? ImageUrl) : ICreatorSearchCandidate
{
    /// <summary>A book's identity is its title plus its author - see <see cref="ReferenceMatchRules"/>.</summary>
    public string? Creator => Author;
}

public record BookDetails(string ExternalId, string Title, int? Year, string? Synopsis, string? Author, string? AuthorExternalId, List<string> Genres, string? ImageUrl, string? Language = null, string? Isbn = null, double? Rating = null, int? RatingCount = null);

/// <summary>
/// Provider-agnostic book lookup, backing <see cref="ReferenceEnrichmentService"/>'s book resolution/refresh
/// and <see cref="ReferenceDataAdminController"/>'s admin search. Which concrete implementation is active is
/// a deployment-time choice (<c>ReferenceData:BookProvider</c>, see <c>Program.cs</c>) - nothing outside the
/// implementation itself (see <see cref="IReferenceProviderClient.ProviderKey"/>) should assume which provider
/// is behind this interface. Interface exists so tests use a fake - never call a real provider's API from a test.
/// </summary>
public interface IBookReferenceClient : IReferenceProviderClient
{
    /// <summary>
    /// <paramref name="author"/> narrows the query when known - without it, a common title can return
    /// dozens of unrelated results. <paramref name="year"/> is an optional hint; no implementation currently
    /// sends it as a server-side filter, each for its own confirmed reason (see
    /// <see cref="BookReferenceClientBase.SearchByTitleAsync"/>). It is still returned per candidate for the
    /// caller/admin to use when picking. <paramref name="isbn"/>, when supplied, is an exact identifier and
    /// is tried first as the sole query, superseding title/author entirely, since an ISBN uniquely identifies
    /// an edition; <b>every</b> implementation now searches by it, and a catalogue that doesn't index that
    /// edition widens to the title search rather than reporting nothing.
    /// <para>
    /// The ordering and the fallbacks between those queries are implemented once in
    /// <see cref="BookReferenceClientBase"/>; an implementation supplies only its own query shapes.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default);

    Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Looks up an aggregate book rating by ISBN. A small, single-purpose capability kept off
/// <see cref="IBookReferenceClient"/> because only one provider needs to implement it: it's a cross-provider
/// fallback for the rating field alone. The default book provider (Google Books) no longer serves ratings at
/// all (confirmed against the live API), so a book linked through it - or any provider without ratings - can
/// still get one from Open Library via the clean ISBN the link already resolved. Implemented by
/// <see cref="OpenLibraryClient"/>.
/// </summary>
public interface IBookRatingByIsbnLookup
{
    Task<(double? Average, int? Count)> GetRatingByIsbnAsync(string isbn, CancellationToken cancellationToken = default);
}
