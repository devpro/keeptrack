namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The search policy every <see cref="IBookReferenceClient"/> shares, written once instead of copied per
/// provider: try the narrowest query first, widen whenever a narrowing produced nothing, and never let an
/// optional narrowing parameter silently zero out results a broader search would have found. Each provider
/// supplies only its own two query shapes (<see cref="SearchByIsbnAsync"/>/<see cref="SearchByTitleAsync"/>);
/// the order they are attempted in, and the fallbacks between them, live here.
/// <para>
/// The author fallback below was previously duplicated verbatim in all three clients - the same algorithm
/// over three different query builders, which is exactly the shape that drifts.
/// </para>
/// </summary>
public abstract class BookReferenceClientBase : IBookReferenceClient
{
    /// <inheritdoc />
    public abstract string ProviderKey { get; }

    /// <inheritdoc />
    public abstract string DisplayName { get; }

    /// <inheritdoc />
    public async Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null,
        CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrEmpty(isbn))
        {
            var byIsbn = await SearchByIsbnAsync(isbn, cancellationToken);

            // An ISBN identifies one edition exactly, so a hit is always better than anything a title match
            // could produce and is returned as-is. A MISS, though, is not an answer - it usually means this
            // catalogue simply doesn't index that edition (confirmed: BnF holds no record at all for
            // 9782265002104, which Open Library resolves in one call), and returning nothing there would make
            // an ISBN strictly worse to supply than to leave blank. So a miss falls through to the title
            // search below rather than short-circuiting, the same "an optional narrowing parameter must never
            // silently zero out results" rule the author fallback exists for.
            // No new mis-linking risk: the fallback runs the exact query an ISBN-less item already runs, and
            // automatic resolution still only acts on a single confident candidate.
            if (byIsbn.Count > 0) return byIsbn;
        }

        var results = await SearchByTitleAsync(title, author, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // A tenant's plain author text can fail to match a provider's own creator indexing (a middle name,
            // a diacritic, "and" vs "&", BnF's "LastName, FirstName (dates). Role" shape, a Discogs-style
            // "Artist (2)" disambiguation suffix) even when the title alone finds the book.
            results = await SearchByTitleAsync(title, null, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// Looks the book up by exact identifier. Returning an empty list is a supported outcome and means
    /// "this catalogue doesn't index that edition" - <see cref="SearchBooksAsync"/> widens from there.
    /// </summary>
    protected abstract Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken);

    /// <summary>
    /// Looks the book up by title, narrowed by <paramref name="author"/> when one is given.
    /// <para>
    /// Takes no year on purpose: no book provider here sends one as a server-side filter, each for its own
    /// confirmed reason (Open Library's <c>first_publish_year</c> is the work's original year rather than the
    /// tenant's edition; BnF's "and" clause is not a strict intersection, so stacking a second one compounds
    /// the risk; Google Books needs no year to rank a title well). The year is still returned per candidate
    /// for the admin to pick with, so it is a display/tie-break value, never a query criterion.
    /// </para>
    /// </summary>
    protected abstract Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken);

    /// <inheritdoc />
    public abstract Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
