namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The search policy of every <see cref="IBookReferenceClient"/>, written once: the narrowest query first, widening whenever a narrowing found nothing, so an optional parameter never hides what a broader search finds.
/// Each provider supplies only its two query shapes (<see cref="SearchByIsbnAsync"/>, <see cref="SearchByTitleAsync"/>), and the order and fallbacks live here.
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

            // An ISBN identifies one edition, so a hit beats any title match and is returned as is.
            // A miss usually means this catalogue does not index that edition (BnF has no record of 9782265002104, which Open Library finds), so it falls through to the title search rather than making an ISBN worse than none.
            // That adds no risk of a wrong link: it is the query an item without an ISBN runs, and automatic resolution still needs a confirmed candidate.
            if (byIsbn.Count > 0) return byIsbn;
        }

        var results = await SearchByTitleAsync(title, author, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // a tenant's author text can miss the provider's indexing (a middle name, a diacritic, "and" or "&", BnF's "LastName, FirstName (dates). Role") although the title alone finds the book
            results = await SearchByTitleAsync(title, null, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// Looks the book up by exact identifier.
    /// An empty list means this catalogue does not index that edition, and <see cref="SearchBooksAsync"/> widens from there.
    /// </summary>
    protected abstract Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken);

    /// <summary>
    /// Looks the book up by title, narrowed by <paramref name="author"/> when one is given.
    /// <para>
    /// It takes no year, since no book provider sends one as a filter, each for its own reason.
    /// Open Library's <c>first_publish_year</c> is the work's original year, not the edition's, BnF's "and" clause is not a strict intersection, and Google Books ranks a title well without one.
    /// Each candidate still reports its year, for display and tie-breaks, never as a query criterion.
    /// </para>
    /// </summary>
    protected abstract Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken);

    /// <inheritdoc />
    public abstract Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
