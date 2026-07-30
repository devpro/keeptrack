using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// Builds the reference <c>Ratings</c> map for a book, keyed by the provider that resolved it
    /// (a book links through exactly one provider, so the map holds at most one entry - that provider is
    /// therefore the primary). Google Books and Open Library both report a 0-5 average; BnF reports none.
    /// A 0/absent value is omitted, never stored as a real zero.
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

    /// <summary>The book's single stored rating (from whichever provider linked it, or the OL fallback), or (null, null) when it has none.</summary>
    private static (double? Value, double? Scale) BookPrimaryRating(BookReferenceModel reference) =>
        reference.Ratings.Count == 0 ? (null, null) : PrimaryRating(reference.Ratings, reference.Ratings.Keys.First());

    private const string OpenLibraryProviderKey = "openlibrary";

    /// <summary>
    /// Cross-provider rating fallback for books: when the linking provider supplied no rating (Google Books,
    /// the default, no longer serves any) and there's a resolved ISBN to look up by, fetch Open Library's
    /// rating by ISBN and store it under its own source key. No-op when a rating already exists, the linking
    /// provider IS Open Library (already covered), or there's no ISBN. Best-effort - a failed/empty lookup
    /// just leaves the book unrated rather than failing the resolve.
    /// </summary>
    private async Task AddOpenLibraryRatingFallbackAsync(Dictionary<string, ReferenceRatingModel> ratings, string providerKey, string? isbn, CancellationToken cancellationToken)
    {
        if (ratings.Count > 0 || providerKey == OpenLibraryProviderKey || string.IsNullOrWhiteSpace(isbn)) return;

        var (average, count) = await bookRatingByIsbnLookup.GetRatingByIsbnAsync(isbn, cancellationToken);
        if (average is > 0)
        {
            ratings[OpenLibraryProviderKey] = new ReferenceRatingModel { Value = average.Value, Scale = 5, Count = count };
        }
    }

    /// <summary>
    /// User-triggered "check for reference match" for books - see
    /// <see cref="TryLinkExistingTvShowReferenceAsync"/> for the full rationale (this is the same local-only,
    /// no-HTTP-call lookup, just against <c>book_reference</c>). A successful match also sets
    /// <see cref="BookModel.Year"/>, <see cref="BookModel.Author"/>, <see cref="BookModel.Genre"/>,
    /// <see cref="BookModel.Language"/> and <see cref="BookModel.Isbn"/> to the reference's canonical values -
    /// the author's name is joined from <see cref="PersonReferenceModel"/> via
    /// <see cref="BookReferenceModel.AuthorReferenceId"/>, and Genre from <see cref="BookReferenceModel.Genres"/>
    /// (joined into the same single free-text field the tenant can otherwise edit by hand).
    /// </summary>
    public async Task<BookModel> TryLinkExistingBookReferenceAsync(BookModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // see TryLinkExistingTvShowReferenceAsync's own comment - the title-only fallback must not run when
        // the tenant has a specific year that simply has no confirmed alias
        var reference = await bookReferenceRepository.FindByTitleYearAsync(model.Title, model.Year, model.Author);
        if (reference is null && model.Year is null)
        {
            reference = await bookReferenceRepository.FindByTitleAsync(model.Title, model.Author);
        }

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                model.ReferenceRating = null;
                model.ReferenceRatingScale = null;
                await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;
        var authorName = await ResolvePersonNameAsync(reference.AuthorReferenceId);
        var genre = JoinGenres(reference.Genres);
        var (ratingValue, ratingScale) = BookPrimaryRating(reference);

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        if (!string.IsNullOrEmpty(authorName)) model.Author = authorName;
        if (genre is not null) model.Genre = genre;
        if (reference.Language is not null) model.Language = reference.Language;
        if (reference.Isbn is not null) model.Isbn = reference.Isbn;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await bookRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, authorName, genre, reference.Language, reference.Isbn, ratingValue, ratingScale);

        return model;
    }

    /// <summary>
    /// Admin-triggered "unlink" for books - see <see cref="UnlinkTvShowReferenceAsync"/> for the full
    /// rationale (clears the tenant's link and permanently deletes the shared reference document, rather
    /// than only detaching this one item).
    /// </summary>
    public async Task<BookModel> UnlinkBookReferenceAsync(BookModel model)
    {
        var referenceId = model.ReferenceId;
        model.ReferenceId = string.Empty;
        model.ReferenceRating = null;
        model.ReferenceRatingScale = null;
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await bookReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for books - see <see cref="TryAutoResolveTvShowAsync"/>. Always searches
    /// the deployment's *default* provider (<see cref="BookReferenceClientRegistry.Resolve"/> with a null
    /// key) - this is the unattended background path, so there's no admin picking a provider here. Passing
    /// <paramref name="author"/> narrows the search considerably - without it, a common title easily
    /// returns more than one candidate and the match is correctly left for the admin queue.
    /// <paramref name="isbn"/> is always null on this path today (the Add form doesn't collect it, only the
    /// detail page does), but threaded through anyway so this stays the single place that decides how a
    /// search is issued.
    /// </summary>
    public async Task TryAutoResolveBookAsync(string title, int? year, string? author = null, string? isbn = null)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        var client = bookReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchBooksAsync(title, year, author, isbn);
        if (candidates.Count != 1) return;
        await ResolveBookAsync(title, year, candidates[0].ExternalId, client.ProviderKey, isbn);
    }

    /// <summary>
    /// Resolves a title+year to a specific book provider id, upserts the reference document, and
    /// propagates the link - see <see cref="ResolveTvShowAsync"/>. <paramref name="providerKey"/> is which
    /// registered <see cref="IBookReferenceClient"/> <paramref name="externalId"/> came from - required from
    /// the admin's manual link action (an id is meaningless without knowing which provider issued it once
    /// more than one is registered), defaults to the deployment default for the automatic path above.
    /// <paramref name="isbn"/> is the ISBN that was actually supplied as search input (if any) - it only
    /// ever feeds the *tenant-search* alias entry (what the caller actually searched with), never the
    /// canonical one (which always uses whatever the provider itself reports, <see cref="BookDetails.Isbn"/>,
    /// regardless of what was searched for) - see <see cref="MergeMatchedAliases"/>.
    /// </summary>
    public async Task<BookReferenceModel> ResolveBookAsync(string title, int? year, string externalId, string? providerKey = null, string? isbn = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var client = bookReferenceClientRegistry.Resolve(providerKey);
        var details = await client.GetBookDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Book {externalId} could not be fetched from {client.ProviderKey}.");

        // see ResolveTvShowAsync's own comment - the title-only fallback (which reuses existing.Id for the
        // upsert) must not run when year is known but simply unconfirmed yet, or it risks overwriting an
        // unrelated same-titled reference document instead of just linking wrong
        var existing = await bookReferenceRepository.FindByExternalIdAsync(client.ProviderKey, externalId)
                       ?? (details.Author is not null ? await bookReferenceRepository.FindByTitleYearAsync(title, year, details.Author) : null);
        if (existing is null && year is null && details.Author is not null)
        {
            existing = await bookReferenceRepository.FindByTitleAsync(title, details.Author);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds[client.ProviderKey] = externalId;

        var authorReferenceId = !string.IsNullOrEmpty(details.AuthorExternalId)
            ? await ResolvePersonReferenceIdAsync(client.ProviderKey, details.AuthorExternalId, details.Author ?? "Unknown", null)
            : existing?.AuthorReferenceId;

        var ratings = BuildBookRatings(client.ProviderKey, details.Rating, details.RatingCount);
        await AddOpenLibraryRatingFallbackAsync(ratings, client.ProviderKey, details.Isbn ?? existing?.Isbn, CancellationToken.None);

        var model = new BookReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            AuthorReferenceId = authorReferenceId,
            ExternalIds = externalIds,
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases,
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
        var (ratingValue, ratingScale) = BookPrimaryRating(saved);
        await bookRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, details.Author, JoinGenres(details.Genres), details.Language, details.Isbn, ratingValue, ratingScale);
        return saved;
    }

    /// <summary>
    /// Re-fetches a book reference from whichever registered provider it was actually linked through,
    /// always doing a full re-fetch when called (unlike TMDB, none of the book providers currently
    /// supported expose a per-id "has this changed" endpoint, so there's no cheap pre-check to skip it) -
    /// see <see cref="RefreshTvShowReferenceAsync"/> for the shared staleness-cutoff mechanism this is
    /// invoked from. Looks up <see cref="BookReferenceModel.ExternalIds"/> against every *currently
    /// registered* provider, not just the deployment default - a reference linked via a non-default
    /// provider must keep refreshing even if the default later changes (this used to only ever check the
    /// single configured client's key, so a reference linked through any other provider silently stopped
    /// refreshing forever). A no-op (returns unchanged) when no registered provider's id is present, or the
    /// provider no longer has details for it.
    /// </summary>
    public async Task<(BookReferenceModel Model, bool DataChanged)> RefreshBookReferenceAsync(BookReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var client = bookReferenceClientRegistry.All.FirstOrDefault(c => reference.ExternalIds.ContainsKey(c.ProviderKey));
        if (client is null) return (reference, false);

        var externalId = reference.ExternalIds[client.ProviderKey];
        var details = await client.GetBookDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

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
        await AddOpenLibraryRatingFallbackAsync(reference.Ratings, client.ProviderKey, reference.Isbn, cancellationToken);
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, details.Author, details.Isbn));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await bookReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale) = BookPrimaryRating(saved);
        await bookRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale);
        return (saved, true);
    }
}
