using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves a tracked item's title+year to a shared reference document and propagates its id to every tenant's matching document.
/// Shared by both the automatic (best-effort, background) path and the admin manual-linking path so the "resolve and propagate" logic is never duplicated between them - only how an external id gets picked differs.
/// Split into one partial-class file per domain (<c>.TvShowsAndMovies.cs</c>, <c>.Books.cs</c>, <c>.VideoGames.cs</c>, <c>.Albums.cs</c>) since each domain's five-method template (TryLinkExisting/TryAutoResolve/Resolve/Refresh) is sizeable on its own; this file holds the shared constructor and the cross-domain helpers.
/// <para>
/// Which (title, year, creator, isbn) combinations a resolve is allowed to remember is not decided here: it is <see cref="ReferenceAliasRule"/>, one declaration per domain, read by every path that writes an alias.
/// </para>
/// </summary>
public partial class ReferenceEnrichmentService(
    ITmdbClient tmdbClient,
    IOmdbClient omdbClient,
    IOmdbCallBudget omdbCallBudget,
    ReferenceClientRegistry<IBookReferenceClient> bookReferenceClientRegistry,
    IBookRatingByIsbnLookup bookRatingByIsbnLookup,
    ReferenceClientRegistry<IVideoGameReferenceClient> videoGameReferenceClientRegistry,
    IDiscogsClient discogsClient,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IPersonReferenceRepository personReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IAlbumReferenceRepository albumReferenceRepository,
    ITvShowRepository tvShowRepository,
    IMovieRepository movieRepository,
    IBookRepository bookRepository,
    IVideoGameRepository videoGameRepository,
    IAlbumRepository albumRepository,
    IAppSettingRepository appSettingRepository,
    RatingSourceOptions ratingSourceOptions,
    ILogger<ReferenceEnrichmentService> logger)
{
    /// <summary>
    /// The primary rating source for <paramref name="domain"/> - the source whose value/scale is denormalized
    /// onto tenant items as the list pill / sort value. The admin's stored override (see
    /// <see cref="IAppSettingRepository"/>) when it names a source the domain currently offers, otherwise the
    /// code default (<see cref="RatingSourceOptions.DefaultSource"/>). An override naming a source that is not
    /// on offer is ignored rather than trusted - and left stored, so a provider change is reversible.
    /// </summary>
    public async Task<string> GetPrimaryRatingSourceAsync(ReferenceItemType domain)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        return ratingSourceOptions.Resolve(overrides, domain);
    }

    /// <summary>
    /// Re-applies the current primary rating source (see <see cref="GetPrimaryRatingSourceAsync"/>) to every
    /// already-linked tenant item across a domain, re-stamping the denormalized
    /// <c>ReferenceRating</c>/<c>ReferenceRatingScale</c>/<c>ReferenceRatingSource</c> from each reference
    /// document's <c>Ratings</c> dict. Backs the admin "recompute" action after switching a domain's source -
    /// one bulk <c>SetReferenceRatingAsync</c> pass per reference, no provider calls (unlike the full sync).
    /// Small, shared reference collection, so this runs synchronously rather than as a background job.
    /// <para>
    /// It starts by asking whether any linked item is still on a different source, and does nothing at all
    /// when none is - the common case, since the action is right next to the source picker and gets clicked
    /// again "just in case". Without the stamp there was nothing to ask: the pass had to read the whole
    /// reference collection and fire an <c>UpdateMany</c> per document, every one of them setting values that
    /// were already correct. Items linked before the stamp existed count as mismatched, so the first
    /// recompute backfills them and no migration script is needed.
    /// </para>
    /// </summary>
    /// <remarks>
    /// A value that drifted while the source stayed the same is deliberately not what this repairs - that's
    /// the periodic sync's job, which re-propagates through the same <c>SetReferenceRatingAsync</c> whenever
    /// it refreshes a reference.
    /// </remarks>
    public async Task<(int ReferencesChecked, long ItemsUpdated)> RecomputeReferenceRatingsAsync(ReferenceItemType domain)
    {
        var source = await GetPrimaryRatingSourceAsync(domain);
        return domain switch
        {
            ReferenceItemType.Movie => await RecomputeReferenceRatingsAsync(
                movieRepository.CountLinkedOnOtherRatingSourceAsync,
                movieReferenceRepository.FindRatingsAsync,
                movieRepository.SetReferenceRatingsAsync,
                source),
            ReferenceItemType.TvShow => await RecomputeReferenceRatingsAsync(
                tvShowRepository.CountLinkedOnOtherRatingSourceAsync,
                tvShowReferenceRepository.FindRatingsAsync,
                tvShowRepository.SetReferenceRatingsAsync,
                source),
            ReferenceItemType.VideoGame => await RecomputeReferenceRatingsAsync(
                videoGameRepository.CountLinkedOnOtherRatingSourceAsync,
                videoGameReferenceRepository.FindRatingsAsync,
                videoGameRepository.SetReferenceRatingsAsync,
                source),
            _ => throw new ArgumentOutOfRangeException(nameof(domain), $"Rating source is not admin-selectable for {domain}.")
        };
    }

    /// <summary>
    /// How many references one round trip carries, in both directions: the size of a projected read page and
    /// of the bulk write it produces. One knob rather than two that would have to agree, and it is what keeps
    /// a recompute's memory flat no matter how large the reference collection or the user base gets.
    /// </summary>
    private const int RecomputeBatchSize = 500;

    /// <summary>
    /// Domain-agnostic recompute loop - each domain only differs in which reference collection it reads and
    /// which tenant collection it re-propagates through, so the iteration itself lives once here (adding
    /// books/albums later is a one-line switch arm above, never a copy of this loop).
    /// <para>
    /// A batch is one projected read and one bulk write, so the whole pass costs two round trips per 500
    /// references and none per tenant item: the items are re-stamped server-side inside each entry's
    /// <c>UpdateMany</c>. That is the property that matters as the app grows - more users mean more documents
    /// written per reference, but not more round trips, more payload, or more memory here. It used to be one
    /// <c>UpdateMany</c> round trip per reference, on top of reading every reference document whole.
    /// </para>
    /// </summary>
    private static async Task<(int ReferencesChecked, long ItemsUpdated)> RecomputeReferenceRatingsAsync(
        Func<string, Task<long>> countOnOtherSource,
        Func<string?, int, Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>>> findRatings,
        Func<IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)>, Task<long>> setRatings,
        string source)
    {
        // one counted query decides whether there is any work; nothing is read or written when there isn't
        if (await countOnOtherSource(source) == 0) return (0, 0);

        var referencesChecked = 0;
        long itemsUpdated = 0;
        string? afterId = null;

        while (true)
        {
            var batch = await findRatings(afterId, RecomputeBatchSize);
            if (batch.Count == 0) break;

            var updates = new List<(string ReferenceId, double? Rating, double? RatingScale, string? Source)>(batch.Count);
            foreach (var (id, ratings) in batch)
            {
                var (value, scale, stampedSource) = PrimaryRating(ratings, source);
                updates.Add((id, value, scale, stampedSource));
            }

            itemsUpdated += await setRatings(updates);
            referencesChecked += batch.Count;
            afterId = batch[^1].Id;

            // a short page is the last one - stop rather than pay for a query that can only come back empty
            if (batch.Count < RecomputeBatchSize) break;
        }

        return (referencesChecked, itemsUpdated);
    }

    /// <summary>
    /// Reuses a reference document the local collection already holds, if any, and reports whether it did - the first thing every <c>TryAutoResolve*Async</c> does, before a provider is contacted.
    /// <para>
    /// A stored alias <b>is</b> the answer: someone already established that this title (and year, or creator) means that work, so re-deriving it from a provider is at best a slower way to the same document and at worst a different one - these searches are fuzzy, and the rule that reads them deliberately refuses anything it cannot confirm.
    /// The item then waits for a human instead of linking to a fact the database was holding all along.
    /// </para>
    /// <para>
    /// It matters most exactly where the collection is most useful: a tenant adding a film someone else already tracks, and every row of a bulk import of them.
    /// Creating an item used to go straight to the provider every time.
    /// </para>
    /// </summary>
    private static async Task<bool> TryLinkKnownReferenceAsync<TReference>(Func<Task<TReference?>> findKnown, Func<TReference, Task> propagate)
        where TReference : class
    {
        var known = await findKnown();
        if (known is null) return false;

        await propagate(known);
        return true;
    }

    /// <summary>
    /// Merges a fresh fetch's ratings into whatever a reference document already carries, replacing only the
    /// sources <paramref name="providerSources"/> says this provider speaks for.
    /// <para>
    /// A domain with more than one provider needs this, and video games are the case: a reference linked
    /// through RAWG and later refreshed through IGDB must keep its <c>rawg</c>/<c>metacritic</c> values, and
    /// vice versa. Assigning the fetched map wholesale - which every domain used to do, back when each had
    /// exactly one provider - would silently discard scores that are still perfectly good and still displayed
    /// on the detail page. Same reasoning as <c>RebuildRatingsAsync</c> keeping a known IMDb value when OMDb
    /// was never asked, just generalized from one source to a provider's whole set.
    /// </para>
    /// <para>
    /// A source the provider *does* own but no longer reports is correctly dropped: that is this provider
    /// saying it has no value, which is an answer, not an absence.
    /// </para>
    /// </summary>
    private static Dictionary<string, ReferenceRatingModel> MergeProviderRatings(
        Dictionary<string, ReferenceRatingModel>? existing,
        Dictionary<string, ReferenceRatingModel>? fresh,
        IReadOnlyList<string> providerSources)
    {
        var merged = new Dictionary<string, ReferenceRatingModel>();
        foreach (var (source, rating) in existing ?? [])
        {
            if (!providerSources.Contains(source)) merged[source] = rating;
        }

        foreach (var (source, rating) in fresh ?? [])
        {
            merged[source] = rating;
        }

        return merged;
    }

    /// <summary>
    /// Dedupes a single credited individual/group into the shared, owner-less <c>person_reference</c>
    /// collection by external provider id, returning the id of the (possibly just-created) document.
    /// Shared by TV/movie cast (<see cref="ResolveCastAsync"/>, one call per credited member), book authors,
    /// and album artists - "Person" already meant "a named individual or group identified by an external
    /// provider id", not "actor" specifically, so extending its use here needed no rename, just reuse.
    /// </summary>
    private async Task<string> ResolvePersonReferenceIdAsync(string provider, string externalId, string name, string? imageUrl)
    {
        var existing = await personReferenceRepository.FindByExternalIdAsync(provider, externalId);
        var person = new PersonReferenceModel
        {
            Id = existing?.Id,
            Name = name,
            ProfileImageUrl = imageUrl ?? existing?.ProfileImageUrl,
            ExternalIds = existing?.ExternalIds ?? new Dictionary<string, string> { [provider] = externalId }
        };
        var saved = await personReferenceRepository.UpsertAsync(person);
        return saved.Id!;
    }

    /// <summary>
    /// Looks up a person_reference document's <see cref="PersonReferenceModel.Name"/> by id - the inverse
    /// of <see cref="ResolvePersonReferenceIdAsync"/>, used when propagating a book's author/album's artist
    /// name onto the tenant's own document (see <see cref="TryLinkExistingBookReferenceAsync"/>/
    /// <see cref="TryLinkExistingAlbumReferenceAsync"/>).
    /// </summary>
    private async Task<string?> ResolvePersonNameAsync(string? personReferenceId)
    {
        if (string.IsNullOrEmpty(personReferenceId)) return null;
        var person = await personReferenceRepository.FindByIdAsync(personReferenceId);
        return person?.Name;
    }

    /// <summary>
    /// Joins a reference document's <c>Genres</c> list into the single free-text <c>Genre</c> field Book/Album
    /// tenants own (there's no equivalent list on those two models - Genre there is a plain user-editable
    /// string, same shape as <see cref="BookModel.Author"/>/<see cref="AlbumModel.Artist"/> before linking).
    /// Null (not overwritten) when the reference has no genres, same "don't overwrite with nothing" rule
    /// <see cref="TryLinkExistingBookReferenceAsync"/>/<see cref="TryLinkExistingAlbumReferenceAsync"/> already
    /// apply to Author/Artist/Year.
    /// </summary>
    private static string? JoinGenres(List<string> genres) => genres.Count > 0 ? string.Join(", ", genres) : null;
}
