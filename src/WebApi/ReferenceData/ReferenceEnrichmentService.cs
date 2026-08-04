using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves a tracked item's title+year to a shared reference document and propagates its id to every
/// tenant's matching document. Shared by both the automatic (best-effort, background) path and the
/// admin manual-linking path so the "resolve and propagate" logic is never duplicated between them -
/// only how an external id gets picked differs. Split into one partial-class file per domain
/// (<c>.TvShowsAndMovies.cs</c>, <c>.Books.cs</c>, <c>.VideoGames.cs</c>, <c>.Albums.cs</c>) since each
/// domain's five-method template (TryLinkExisting/TryAutoResolve/Resolve/Refresh) is sizeable on its own;
/// this file holds the shared constructor and the one truly cross-domain helper, <see cref="MergeMatchedAliases"/>.
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
    ILogger<ReferenceEnrichmentService> logger)
{
    /// <summary>
    /// The primary rating source for <paramref name="domain"/> - the source whose value/scale is denormalized
    /// onto tenant items as the list pill / sort value. The admin's stored override (see
    /// <see cref="IAppSettingRepository"/>) when it names a source the catalog still offers, otherwise the
    /// code default (<see cref="RatingSourceCatalog.DefaultSource"/>). An override naming a source no longer
    /// available is ignored rather than trusted, so removing a source from the catalog can't strand an item.
    /// </summary>
    public async Task<string> GetPrimaryRatingSourceAsync(ReferenceItemType domain)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        return RatingSourceCatalog.Resolve(overrides, domain);
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
    /// Combines whatever (title, year, creator, isbn) combinations a reference document already remembered
    /// with the new ones just confirmed (e.g. the provider's canonical (title, year) and the (title, year)
    /// the tenant actually searched with, which may differ from canonical in either field). Deduplicated,
    /// with title/creator normalized. Shared by every domain - the alias shape
    /// (<see cref="Domain.Models.ReferenceMatchModel"/>) is deliberately generic, not per-domain.
    /// <paramref name="aliases"/>' <c>Creator</c> is null for TV show/movie/video game (no creator dimension
    /// in their match key); Book/Album always pass their resolved author/artist text - see
    /// <see cref="ReferenceMatchModel.Creator"/> for why it matters there. <c>Isbn</c> is null for every
    /// domain but Book, and null even for Book unless an ISBN was genuinely part of that specific
    /// match/search - see <see cref="ReferenceMatchModel.Isbn"/>: an exact-identifier field must never be
    /// backfilled from data that wasn't actually used to find the match.
    /// </summary>
    /// <remarks>
    /// The dedup check itself is <see cref="ReferenceMatchModel.Matches"/>, so this and the reference-data
    /// import agree on what "already recorded" means. It compares <c>Creator</c> directly (no null/empty-string normalization needed here):
    /// <c>DataStorageMappingProfile</c>'s <c>ReferenceMatchModel</c> -&gt; <c>ReferenceMatch</c> map opts
    /// <c>Creator</c> out of the profile-wide <c>AllowNullDestinationValues = false</c> (<c>.ForMember(x =>
    /// x.Creator, opt => opt.AllowNull())</c>), so a null <c>Creator</c> round-trips through Mongo as an
    /// actual BSON null, not <c>""</c> - keeping that distinction the database layer's job instead of a
    /// workaround here. Getting this wrong once already duplicated an alias on every re-resolve/re-refresh
    /// (confirmed against a real video game reference, RAWG's "God of War", that had accumulated an exact
    /// duplicate this way) - see `scripts/dedupe-matched-aliases.js` for the one-off cleanup this needed.
    /// </remarks>
    private static List<Domain.Models.ReferenceMatchModel> MergeMatchedAliases(List<Domain.Models.ReferenceMatchModel>? existing, params (string Title, int? Year, string? Creator, string? Isbn)[] aliases)
    {
        var result = new List<Domain.Models.ReferenceMatchModel>(existing ?? []);
        foreach (var (title, year, creator, isbn) in aliases)
        {
            var normalized = TitleNormalizer.Normalize(title);
            var normalizedCreator = creator is null ? null : TitleNormalizer.Normalize(creator);
            if (!result.Any(m => m.Matches(normalized, year, normalizedCreator, isbn)))
            {
                result.Add(new Domain.Models.ReferenceMatchModel { Title = normalized, Year = year, Creator = normalizedCreator, Isbn = isbn });
            }
        }

        return result;
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
