using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// A book's <c>Ratings</c> map, keyed by the provider that resolved it, so at most one entry, which is the primary.
    /// Google Books and Open Library report a 0 to 5 average, BnF none.
    /// A zero or absent value is omitted.
    /// </summary>
    private static Dictionary<string, ReferenceRatingModel> BuildBookRatings(string providerKey, double? rating, int? ratingCount)
    {
        var ratings = new Dictionary<string, ReferenceRatingModel>();
        if (rating is > 0)
        {
            ratings[providerKey] = new ReferenceRatingModel { Value = rating.Value, Scale = 5, Count = ratingCount };
        }
        return ratings;
    }

    /// <summary>
    /// The book's single stored rating, from the linking provider or the Open Library fallback, with that key as its source, or nothing.
    /// Books have no selectable source, so the key is read from the reference.
    /// </summary>
    private static (double? Value, double? Scale, string? Source) BookPrimaryRating(BookReferenceModel reference) =>
        reference.Ratings.Count == 0 ? (null, null, null) : PrimaryRating(reference.Ratings, reference.Ratings.Keys.First());

    private const string OpenLibraryProviderKey = "openlibrary";

    /// <summary>
    /// The rating fallback for books: when the linking provider gave no rating (Google Books gives none) and an ISBN is known, Open Library's rating by ISBN is stored under its own key.
    /// Nothing happens when a rating exists, the linking provider is Open Library, or there is no ISBN.
    /// <para>
    /// <b>It runs on the background refresh only</b> (<see cref="RefreshBookReferenceAsync"/>), never while someone waits.
    /// Google Books serving no ratings, it would otherwise run on every link, and an unreachable Open Library would spend the whole 40s book budget on an admin's click.
    /// </para>
    /// <para>
    /// It never throws: a secondary provider adding an optional number must not discard what the linking provider returned.
    /// A slow Open Library would otherwise fail every book refresh, leaving <c>LastEnrichedAt</c> unstamped, so the same books would lead every pass and time out again, as <see cref="IOmdbClient"/> avoids.
    /// </para>
    /// <para>
    /// <paramref name="knownRating"/> matters since the refresh rebuilds <c>Ratings</c> from the linking provider, which never carries this value.
    /// A lookup that never answered keeps the known rating, while an answer of "no rating" clears it, as <c>RebuildRatingsAsync</c> does for OMDb.
    /// </para>
    /// </summary>
    private async Task AddOpenLibraryRatingFallbackAsync(Dictionary<string, ReferenceRatingModel> ratings, string providerKey, string? isbn,
        ReferenceRatingModel? knownRating, CancellationToken cancellationToken)
    {
        if (ratings.Count > 0 || providerKey == OpenLibraryProviderKey) return;

        // no ISBN is no answer either: nothing to ask with, so nothing changed
        if (string.IsNullOrWhiteSpace(isbn))
        {
            KeepKnownRating();
            return;
        }

        try
        {
            var (average, count) = await bookRatingByIsbnLookup.GetRatingByIsbnAsync(isbn, cancellationToken);
            if (average is > 0)
            {
                ratings[OpenLibraryProviderKey] = new ReferenceRatingModel { Value = average.Value, Scale = 5, Count = count };
            }
        }
        // a shutdown is not a provider failure, and swallowing it would walk the rest of the pass against a container being disposed
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(exception, "Open Library rating lookup failed for ISBN {Isbn}; the book keeps the linking provider's data and whatever rating was already known.", isbn);
            KeepKnownRating();
        }

        void KeepKnownRating()
        {
            if (knownRating is not null) ratings[OpenLibraryProviderKey] = knownRating;
        }
    }

    /// <summary>
    /// Carries a stored Open Library rating across a rebuild of <c>Ratings</c>, with no call.
    /// The linking provider never carries it, so linking again would blank a good rating until the next refresh.
    /// <see cref="ResolveBookAsync"/> does this rather than the lookup, so an admin never waits on a second provider.
    /// </summary>
    private static void KeepKnownOpenLibraryRating(Dictionary<string, ReferenceRatingModel> ratings, string providerKey, ReferenceRatingModel? knownRating)
    {
        if (ratings.Count > 0 || providerKey == OpenLibraryProviderKey || knownRating is null) return;

        ratings[OpenLibraryProviderKey] = knownRating;
    }

    /// <summary>
    /// The local half of "check for reference match" for books (see <see cref="TryLinkExistingTvShowReferenceAsync"/>), against <c>book_reference</c>.
    /// A match also sets <see cref="BookModel.Year"/>, <see cref="BookModel.Author"/> (the name of <see cref="BookReferenceModel.AuthorReferenceId"/>'s person), <see cref="BookModel.Genre"/>, <see cref="BookModel.Language"/> and <see cref="BookModel.Isbn"/> to the reference's values.
    /// </summary>
    public async Task<BookModel> TryLinkExistingBookReferenceAsync(BookModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        var reference = await FindKnownBookReferenceAsync(model.Title, model.Year, model.Author, model.Isbn);

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                model.ReferenceRating = null;
                model.ReferenceRatingScale = null;
                model.ReferenceRatingSource = null;
                await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var authorName = await ResolvePersonNameAsync(reference.AuthorReferenceId);
        var genre = JoinGenres(reference.Genres);
        var (ratingValue, ratingScale, ratingSource) = BookPrimaryRating(reference);

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        if (!string.IsNullOrEmpty(authorName)) model.Author = authorName;
        if (genre is not null) model.Genre = genre;
        if (reference.Language is not null) model.Language = reference.Language;
        if (reference.Isbn is not null) model.Isbn = reference.Isbn;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);

        return model;
    }

    /// <summary>
    /// The reference this book was already matched to, or null: the local half of every book match path, asked before any provider.
    /// <para>
    /// Three tiers, strongest first.
    /// An <b>ISBN</b> names one printing, so it matches even a translated title.
    /// Then the exact (title, author, year) an alias was confirmed under.
    /// Then <b>title and author alone</b>, where most local matching happens, since a work is republished years apart and a tenant's year often names an unconfirmed edition.
    /// </para>
    /// <para>
    /// The last tier could guess but does not: <c>FindByTitleAsync</c> returns nothing when several references share a title and an author's name.
    /// </para>
    /// </summary>
    private async Task<BookReferenceModel?> FindKnownBookReferenceAsync(string title, int? year, string author, string? isbn)
    {
        if (!string.IsNullOrWhiteSpace(isbn))
        {
            var byIsbn = await bookReferenceRepository.FindByIsbnAsync(isbn);
            if (byIsbn is not null) return byIsbn;
        }

        return await bookReferenceRepository.FindByTitleYearAsync(title, year, author)
               ?? await bookReferenceRepository.FindByTitleAsync(title, author);
    }

    /// <summary>
    /// Book equivalent of <see cref="WriteTvShowLinkAsync"/>.
    /// The author's name is joined from <c>person_reference</c>, since a book reference stores only the id.
    /// </summary>
    private async Task WriteBookLinkAsync(BookReferenceModel reference, ReferenceLinkTarget target)
    {
        var authorName = await ResolvePersonNameAsync(reference.AuthorReferenceId);
        var (ratingValue, ratingScale, ratingSource) = BookPrimaryRating(reference);
        await bookRepository.SetReferenceLinkAsync(target, reference.Id!, reference.Title, reference.Year,
            authorName, JoinGenres(reference.Genres), reference.Language, reference.Isbn, ratingValue, ratingScale, ratingSource);
    }

    /// <summary>
    /// The admin's unlink for books: clears the link and deletes the shared reference (see <see cref="UnlinkTvShowReferenceAsync"/>).
    /// </summary>
    public async Task<BookModel> UnlinkBookReferenceAsync(BookModel model)
    {
        var referenceId = model.ReferenceId;
        model.ReferenceId = string.Empty;
        model.ReferenceRating = null;
        model.ReferenceRatingScale = null;
        model.ReferenceRatingSource = null;
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await bookReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for books (see <see cref="TryAutoResolveTvShowAsync"/>), always through the default provider, since nobody picks one here.
    /// The ISBN is empty on create, the Add form not collecting it, and used when the detail page supplied one.
    /// <para>
    /// <b>A book is its title and its author, never a year</b>: Google Books answers <c>intitle:The Hobbit+inauthor:Tolkien</c> with 300 volumes spanning decades, all one book.
    /// The year breaks ties (<see cref="ReferenceMatchRules.OrderByBestMatch"/>), and an author is required.
    /// </para>
    /// <para>
    /// <b>Several confirmed candidates are editions, not an ambiguity</b>, so the best is linked (see <see cref="ReferenceMatchRules.ConfirmedCreatorMatches"/>), where waiting for one row would link no book.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveBookAsync(BookModel item)
    {
        var title = item.Title;
        var year = item.Year;
        var author = item.Author;
        var isbn = item.Isbn;

        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        // An author is required for any automatic link (owner's rule), as a year is for films, shows and games, since a title alone names several works.
        // Without one the item waits for "check for reference match".
        if (string.IsNullOrWhiteSpace(author)) return;

        // a reference this book was already matched to is the answer (see TryLinkKnownReferenceAsync)
        if (await TryLinkKnownReferenceAsync(
                () => FindKnownBookReferenceAsync(title, year, author, isbn),
                reference => WriteBookLinkAsync(reference, ReferenceLinkTarget.Item(item.Id!, item.OwnerId))))
        {
            return;
        }

        var client = bookReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchBooksAsync(title, year, author, isbn);
        var matches = ReferenceMatchRules.ConfirmedCreatorMatches(candidates, title, author);
        if (matches.Count == 0) return;
        await ResolveBookAsync(title, year, matches[0].ExternalId, ReferenceLinkTarget.Item(item.Id!, item.OwnerId), client.ProviderKey, isbn);
    }

    /// <summary>
    /// "Check for reference match" for books (see <see cref="LinkTvShowReferenceAsync"/>), the field often missing at creation being the <b>author</b> rather than the year.
    /// </summary>
    public async Task<BookModel> LinkBookReferenceAsync(BookModel model)
    {
        model = await TryLinkExistingBookReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        await TryAutoResolveBookAsync(model);
        return await bookRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>
    /// Resolves a title to a book provider id, upserts the reference and links the records <paramref name="target"/> names (see <see cref="ResolveTvShowAsync"/>).
    /// <paramref name="providerKey"/> names the client <paramref name="externalId"/> came from, required for an admin's link since an id means nothing without its provider, and the default for the automatic path.
    /// <paramref name="isbn"/> is the ISBN searched with, if any, feeding only the alias of what was searched, never the canonical one, which uses the provider's <see cref="BookDetails.Isbn"/> (see <see cref="ReferenceAliasRule.TitleAndCreatorWithYear"/>).
    /// </summary>
    public async Task<BookReferenceModel> ResolveBookAsync(string title, int? year, string externalId, ReferenceLinkTarget target, string? providerKey = null, string? isbn = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var client = bookReferenceClientRegistry.Resolve(providerKey);
        var details = await client.GetBookDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Book {externalId} could not be fetched from {client.ProviderKey}.");

        // The provider id is checked first and is authoritative (see ResolveTvShowAsync).
        // The fallback is the identity ladder of the local match path (FindKnownBookReferenceAsync), since a document under another printing's year is still this work and must not be duplicated.
        // It only reuses a document the ladder is sure of, since its last tier refuses to choose.
        var existing = await bookReferenceRepository.FindByExternalIdAsync(client.ProviderKey, externalId)
                       ?? (details.Author is not null ? await FindKnownBookReferenceAsync(title, year, details.Author, isbn ?? details.Isbn) : null);
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds[client.ProviderKey] = externalId;

        var authorReferenceId = !string.IsNullOrEmpty(details.AuthorExternalId)
            ? await ResolvePersonReferenceIdAsync(client.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null)
            : existing?.AuthorReferenceId;

        var ratings = BuildBookRatings(client.ProviderKey, details.Rating, details.RatingCount);
        KeepKnownOpenLibraryRating(ratings, client.ProviderKey, existing?.Ratings.GetValueOrDefault(OpenLibraryProviderKey));

        var model = new BookReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            AuthorReferenceId = authorReferenceId,
            ExternalIds = externalIds,
            MatchedAliases = ReferenceAliasRule.TitleAndCreatorWithYear.Merge(existing?.MatchedAliases,
                (details.Title, details.Year ?? year, details.Author, details.Isbn),
                (title, year, details.Author, isbn)),
            Genres = details.Genres,
            Ratings = ratings,
            ImageUrl = details.ImageUrl,
            Language = details.Language ?? existing?.Language,
            Isbn = details.Isbn ?? existing?.Isbn,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await bookReferenceRepository.UpsertAsync(model);
        var (ratingValue, ratingScale, ratingSource) = BookPrimaryRating(saved);
        await bookRepository.SetReferenceLinkAsync(target, saved.Id!, details.Title, saved.Year, details.Author, JoinGenres(details.Genres), details.Language, details.Isbn, ratingValue, ratingScale, ratingSource);
        return saved;
    }

    /// <summary>
    /// Fetches a book reference again, in full, from the provider it was linked through, since no book provider has a "changed since" endpoint (see <see cref="RefreshTvShowReferenceAsync"/>).
    /// It checks <see cref="BookReferenceModel.ExternalIds"/> against every registered provider, not only the default, so a book linked through another provider keeps refreshing.
    /// Unchanged when no registered provider's id is present, or the provider no longer holds it.
    /// </summary>
    public async Task<(BookReferenceModel Model, bool DataChanged)> RefreshBookReferenceAsync(BookReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var client = bookReferenceClientRegistry.All.FirstOrDefault(c => reference.ExternalIds.ContainsKey(c.ProviderKey));
        if (client is null) return (reference, false);

        var externalId = reference.ExternalIds[client.ProviderKey];
        var details = await client.GetBookDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

        // read before Ratings is rebuilt, since the linking provider never carries it (see AddOpenLibraryRatingFallbackAsync)
        var knownOpenLibraryRating = reference.Ratings.GetValueOrDefault(OpenLibraryProviderKey);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        if (!string.IsNullOrEmpty(details.AuthorExternalId))
        {
            reference.AuthorReferenceId = await ResolvePersonReferenceIdAsync(client.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null);
        }
        reference.Genres = details.Genres;
        reference.Ratings = BuildBookRatings(client.ProviderKey, details.Rating, details.RatingCount);
        reference.ImageUrl = details.ImageUrl ?? reference.ImageUrl;
        reference.Language = details.Language ?? reference.Language;
        reference.Isbn = details.Isbn ?? reference.Isbn;
        await AddOpenLibraryRatingFallbackAsync(reference.Ratings, client.ProviderKey, reference.Isbn, knownOpenLibraryRating, cancellationToken);
        reference.MatchedAliases = ReferenceAliasRule.TitleAndCreatorWithYear.Merge(reference.MatchedAliases, (details.Title, reference.Year, details.Author, details.Isbn));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await bookReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = BookPrimaryRating(saved);
        await bookRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }
}
