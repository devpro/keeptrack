using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

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

    /// <summary>
    /// The book's single stored rating (from whichever provider linked it, or the OL fallback) and that
    /// provider's key as its source, or no value and no source when it has none. Books are the one domain
    /// with no admin-selectable source, so the key is read off the reference rather than resolved.
    /// </summary>
    private static (double? Value, double? Scale, string? Source) BookPrimaryRating(BookReferenceModel reference) =>
        reference.Ratings.Count == 0 ? (null, null, null) : PrimaryRating(reference.Ratings, reference.Ratings.Keys.First());

    private const string OpenLibraryProviderKey = "openlibrary";

    /// <summary>
    /// Cross-provider rating fallback for books: when the linking provider supplied no rating (Google Books,
    /// the default, no longer serves any) and there's a resolved ISBN to look up by, fetch Open Library's
    /// rating by ISBN and store it under its own source key. No-op when a rating already exists, the linking
    /// provider IS Open Library (already covered), or there's no ISBN. Best-effort - a failed/empty lookup
    /// just leaves the book unrated rather than failing the resolve.
    /// <para>
    /// <b>This runs on the background refresh only</b> (<see cref="RefreshBookReferenceAsync"/>), never while someone is waiting.
    /// It was on the interactive link path too, and the guard above made that far worse than it reads: Google Books serves no ratings at all, so <c>ratings.Count > 0</c> is false for every book and the "fallback" fired on every single link.
    /// One admin click therefore called a second provider for a number that has no bearing on the link, and when Open Library is unreachable (measured: no response in 60s) it spent the whole 40s <c>AddBookProviderResilienceHandler</c> budget before this method swallowed the failure.
    /// Linking now costs one Google Books call and the rating catches up on the next sync pass, which is where a slow optional provider belongs.
    /// </para>
    /// <para>
    /// "Best-effort" has to be enforced here, not merely intended: this is a *secondary* provider adding an
    /// optional number to work the linking provider has already returned in full, and an exception escaping it
    /// discards all of that. It did. Open Library's <c>search.json</c> went slow enough to blow the 40s total
    /// timeout (see <c>AddBookProviderResilienceHandler</c>), and every book refresh threw after Google Books
    /// had already answered - so nothing was upserted, <c>LastEnrichedAt</c> was never stamped, and the same
    /// books sat at the head of the staleness queue re-paying that timeout on every pass. Same rule, and the
    /// same reason, as <see cref="IOmdbClient"/> never throwing for anything OMDb or the network can do.
    /// </para>
    /// <para>
    /// <paramref name="knownRating"/> is the other half of that rule, and it matters because the refresh
    /// rebuilds <c>Ratings</c> from the linking provider - which never carries this value. Dropping it whenever
    /// Open Library couldn't be reached would discard a rating that cost a call to obtain, on exactly the
    /// passes where it can't be re-earned (observed: "The Hobbit"'s 4.29/498 disappearing during the outage
    /// above). So a lookup that never answered keeps what is already known, while an answer of "no rating" is
    /// a real answer and does clear it - the same distinction <c>RebuildRatingsAsync</c> makes for OMDb.
    /// </para>
    /// </summary>
    private async Task AddOpenLibraryRatingFallbackAsync(Dictionary<string, ReferenceRatingModel> ratings, string providerKey, string? isbn,
        ReferenceRatingModel? knownRating, CancellationToken cancellationToken)
    {
        if (ratings.Count > 0 || providerKey == OpenLibraryProviderKey) return;

        // no ISBN is not an answer either - there is nothing to ask with, so nothing that could have changed.
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
        // a shutdown is not a provider being unhelpful: swallowing it would walk the rest of the pass against
        // a container already being disposed, the same exclusion ReferenceSyncService's per-document catch makes.
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
    /// Carries an Open Library rating that is already stored across a rebuild of <c>Ratings</c>, with no call to anyone.
    /// The linking provider never carries this value, so re-linking a book would otherwise blank a rating pill that is perfectly good until the next refresh re-earns it.
    /// This is what <see cref="ResolveBookAsync"/> does instead of the lookup above: the number is worth keeping, it is not worth making an admin wait on a second provider to re-fetch it.
    /// </summary>
    private static void KeepKnownOpenLibraryRating(Dictionary<string, ReferenceRatingModel> ratings, string providerKey, ReferenceRatingModel? knownRating)
    {
        if (ratings.Count > 0 || providerKey == OpenLibraryProviderKey || knownRating is null) return;

        ratings[OpenLibraryProviderKey] = knownRating;
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

        var originalTitle = model.Title;
        var originalYear = model.Year;
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
        await bookRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, authorName, genre, reference.Language, reference.Isbn, ratingValue, ratingScale, ratingSource);

        return model;
    }

    /// <summary>
    /// The reference this book has already been matched to by somebody, or null - the local half of every book match path, asked before any provider is.
    /// <para>
    /// Three tiers, strongest key first.
    /// An <b>ISBN</b> names one printing outright, so it answers even when the tenant recorded a translated title nothing else would connect.
    /// Then the exact (title, author, year) an alias was confirmed under.
    /// Then <b>title and author alone</b>, which is where most of this domain's local matching actually happens: one work is republished as revisions years apart, so a tenant's year routinely names an edition nobody has confirmed - Google Books answers <c>intitle:The Hobbit+inauthor:Tolkien</c> with volumes spanning 1981 to 2012, all one book.
    /// Refusing on that would send every reprint to the provider for an answer the collection was already holding.
    /// </para>
    /// <para>
    /// The last tier is the one that could guess, and deliberately does not: <c>FindByTitleAsync</c> returns nothing when several references share a title and an author's name, which is the only case where the year would have been the thing telling them apart.
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
    /// Points every tenant book still recorded under <paramref name="searchTitle"/>/<paramref name="searchYear"/> at <paramref name="reference"/> - see <see cref="PropagateTvShowLinkAsync"/>.
    /// The author's name is joined from <c>person_reference</c>, since a book reference stores only the id.
    /// </summary>
    private async Task PropagateBookLinkAsync(BookReferenceModel reference, string searchTitle, int? searchYear)
    {
        var authorName = await ResolvePersonNameAsync(reference.AuthorReferenceId);
        var (ratingValue, ratingScale, ratingSource) = BookPrimaryRating(reference);
        await bookRepository.SetReferenceLinkAsync(searchTitle, searchYear, reference.Id!, reference.Title, reference.Year,
            authorName, JoinGenres(reference.Genres), reference.Language, reference.Isbn, ratingValue, ratingScale, ratingSource);
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
        model.ReferenceRatingSource = null;
        await bookRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await bookReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for books - see <see cref="TryAutoResolveTvShowAsync"/>. Always searches
    /// the deployment's *default* provider (<see cref="ReferenceClientRegistry{TClient}.Resolve"/> with a null
    /// key) - this is the unattended background path, so there's no admin picking a provider here.
    /// <paramref name="isbn"/> is always null on this path today (the Add form doesn't collect it, only the
    /// detail page does), but threaded through anyway so this stays the single place that decides how a
    /// search is issued.
    /// <para>
    /// <b>A book is identified by its title and its author, never by a year</b>, which is the one place this
    /// domain genuinely differs from films, shows and games rather than merely lagging behind them. Measured
    /// live, Google Books answers <c>intitle:The Hobbit+inauthor:Tolkien</c> with 300 volumes whose first page
    /// alone spans 1981, 1999, 2011 and 2012 - all the same book. So the year is a tie-break here (see
    /// <see cref="ReferenceMatchRules.OrderByBestMatch"/>) and an author is what is required instead.
    /// </para>
    /// <para>
    /// That also means <b>several confirmed candidates are editions rather than an ambiguity</b>, and the best
    /// one is linked rather than the whole set being refused - see
    /// <see cref="ReferenceMatchRules.ConfirmedCreatorMatches"/>. Waiting for the provider to return exactly
    /// one row, which is what this used to do, meant no book could ever link at all: the owner's report, and
    /// exactly what the measurement above predicts.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveBookAsync(string title, int? year, string? author = null, string? isbn = null)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        // An author is required for any automatic link here (owner's rule), the same way a year is required
        // for a film, a show or a game: it is what identifies the work, and a title alone routinely names
        // several. Without one the item waits for the detail page's "check for reference match".
        if (string.IsNullOrWhiteSpace(author)) return;

        // a reference someone already matched this book to is the answer - see TryLinkKnownReferenceAsync
        if (await TryLinkKnownReferenceAsync(
                () => FindKnownBookReferenceAsync(title, year, author, isbn),
                reference => PropagateBookLinkAsync(reference, title, year)))
        {
            return;
        }

        var client = bookReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchBooksAsync(title, year, author, isbn);
        var matches = ReferenceMatchRules.ConfirmedCreatorMatches(candidates, title, author);
        if (matches.Count == 0) return;
        await ResolveBookAsync(title, year, matches[0].ExternalId, client.ProviderKey, isbn);
    }

    /// <summary>
    /// What the detail page's "check for reference match" does for books - see
    /// <see cref="LinkTvShowReferenceAsync"/> for the rationale this shares. The field that is typically
    /// missing at creation time here is the <b>author</b> rather than the year, which is what a book is
    /// identified by, so the dead end this closes is the same one and reached the same way.
    /// </summary>
    public async Task<BookModel> LinkBookReferenceAsync(BookModel model)
    {
        model = await TryLinkExistingBookReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        await TryAutoResolveBookAsync(model.Title, model.Year, model.Author, model.Isbn);
        return await bookRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>
    /// Resolves a title+year to a specific book provider id, upserts the reference document, and propagates the link - see <see cref="ResolveTvShowAsync"/>.
    /// <paramref name="providerKey"/> is which registered <see cref="IBookReferenceClient"/> <paramref name="externalId"/> came from - required from the admin's manual link action (an id is meaningless without knowing which provider issued it once more than one is registered), defaults to the deployment default for the automatic path above.
    /// <paramref name="isbn"/>
    /// is the ISBN that was actually supplied as search input (if any) - it only ever feeds the *tenant-search* alias entry (what the caller actually searched with), never the canonical one (which always uses whatever the provider itself reports, <see cref="BookDetails.Isbn"/>, regardless of what was searched for) - see <see cref="ReferenceAliasRule.TitleAndCreatorWithYear"/>.
    /// </summary>
    public async Task<BookReferenceModel> ResolveBookAsync(string title, int? year, string externalId, string? providerKey = null, string? isbn = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var client = bookReferenceClientRegistry.Resolve(providerKey);
        var details = await client.GetBookDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Book {externalId} could not be fetched from {client.ProviderKey}.");

        // the provider id is checked first and is authoritative - see ResolveTvShowAsync.
        // The fallback is this domain's own identity ladder, the same one the local match path asks (see FindKnownBookReferenceAsync): a document found under another printing's year is still this work, and minting a second reference for it is the outcome to avoid.
        // It can only ever reuse a document the ladder is sure about, since its year-agnostic tier refuses to choose between several.
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
        await bookRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, details.Author, JoinGenres(details.Genres), details.Language, details.Isbn, ratingValue, ratingScale, ratingSource);
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

        // read before Ratings is rebuilt below: the linking provider never carries this value, so it is only
        // recoverable from what is already stored (see AddOpenLibraryRatingFallbackAsync).
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
