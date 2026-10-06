using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One book search hit: title, year, author and cover, enough for automatic matching or for an admin to pick from.
/// </summary>
public record BookSearchResult(string ExternalId, string Title, int? Year, string? Author, string? ImageUrl) : ICreatorSearchCandidate
{
    /// <summary>A book's identity is its title plus its author (see <see cref="ReferenceMatchRules"/>).</summary>
    public string? Creator => Author;
}

public record BookDetails(string ExternalId, string Title, int? Year, string? Synopsis, string? Author, string? AuthorExternalId, List<string> Genres, string? ImageUrl, string? Language = null, string? Isbn = null, double? Rating = null, int? RatingCount = null);

/// <summary>
/// Book lookup independent of the provider, for book resolution and refresh in <see cref="ReferenceEnrichmentService"/> and the admin search.
/// The default implementation is a deployment choice (<c>ReferenceData:BookProvider</c>), so nothing outside an implementation assumes which provider is behind it.
/// An interface, so tests use a fake.
/// </summary>
public interface IBookReferenceClient : IReferenceProviderClient
{
    /// <summary>
    /// <paramref name="author"/> narrows the query when known, since a common title returns dozens of unrelated results.
    /// <paramref name="year"/> is a hint no implementation sends as a filter (see <see cref="BookReferenceClientBase.SearchByTitleAsync"/>), and each candidate still reports its year for picking.
    /// <paramref name="isbn"/>, when given, is tried first as the sole query, since it identifies an edition, and a catalogue not indexing that edition widens to the title search rather than answering nothing.
    /// <para>
    /// The order and fallbacks are written once in <see cref="BookReferenceClientBase"/>, an implementation supplying only its query shapes.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default);

    Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Looks up an aggregate book rating by ISBN.
/// Kept off <see cref="IBookReferenceClient"/>, since only <see cref="OpenLibraryClient"/> implements it, as a fallback for the rating alone.
/// Google Books, the default, serves no ratings, so a book linked through a provider without them gets one from Open Library through its resolved ISBN.
/// </summary>
public interface IBookRatingByIsbnLookup
{
    Task<(double? Average, int? Count)> GetRatingByIsbnAsync(string isbn, CancellationToken cancellationToken = default);
}
