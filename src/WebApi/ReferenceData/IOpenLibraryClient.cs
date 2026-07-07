using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One Open Library search hit - title, year, author and cover, enough for automatic matching or for an
/// admin to pick from when a match is ambiguous.
/// </summary>
public record OpenLibrarySearchResult(string ExternalId, string Title, int? Year, string? Author, string? ImageUrl);

public record OpenLibraryBookDetails(string ExternalId, string Title, int? Year, string? Synopsis, string? Author, string? AuthorExternalId, List<string> Genres, string? ImageUrl);

/// <summary>
/// Thin wrapper over the Open Library REST API (no API key required). Interface exists so tests use a
/// fake - never call the real Open Library API from a test.
/// </summary>
public interface IOpenLibraryClient
{
    /// <summary>
    /// <paramref name="author"/> narrows the query when known (Open Library's own <c>author</c> search
    /// field) - without it, a common title can return dozens of unrelated results. Deliberately does NOT
    /// filter server-side by <paramref name="year"/>: Open Library's <c>first_publish_year</c> is the
    /// work's ORIGINAL publication year, which routinely differs from whatever edition/printing year a
    /// tenant recorded (e.g. a 1997 first edition vs. a 2016 reprint) - filtering on it would silently
    /// drop the real match instead of just ranking it lower. <paramref name="year"/> is still returned per
    /// candidate for the caller/admin to use when picking.
    /// </summary>
    Task<IReadOnlyList<OpenLibrarySearchResult>> SearchBooksAsync(string title, int? year, string? author = null, CancellationToken cancellationToken = default);

    Task<OpenLibraryBookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
