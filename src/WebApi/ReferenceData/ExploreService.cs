using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The Explore feature: suggests acclaimed titles the caller doesn't already track and hasn't dismissed.
/// <para>
/// Reads the locally materialized provider ranking (<c>explore_catalogue</c>, written weekly by
/// <see cref="ExploreCatalogueRefreshService"/>) rather than calling a provider itself. That ranking is the
/// same for every user - only the exclusions below are per-caller - so calling the provider per request was
/// duplicated work, and the handful of pages a request could afford is what once capped Explore at roughly
/// the top 100 titles. Paging a stored, indexed ranking has no such cap.
/// </para>
/// <para>
/// The ordering still follows the admin's primary rating source for the domain, exactly like the rest of the
/// app - it just selects which stored ordering to read instead of which provider call to make. The IMDb
/// wrinkle (IMDb has no catalogue API, so the list stays in TMDB's order with IMDb's number shown on it) is
/// now entirely the refresh pass's business: by read time the value is simply another entry in the stored
/// ratings map.
/// </para>
/// </summary>
public class ExploreService(
    IAppSettingRepository appSettingRepository,
    IExploreCatalogueRepository catalogueRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IVideoGameRepository videoGameRepository,
    IMovieReferenceRepository movieReferenceRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IExploreDismissalRepository dismissalRepository)
{
    /// <summary>
    /// How many ranked entries to read per round-trip while filling a page. Larger than a typical page size
    /// because most entries survive the exclusions; a user who tracks nearly everything just costs a few more
    /// (cheap, indexed) reads.
    /// </summary>
    private const int ScanBatchSize = 100;

    /// <summary>
    /// Upper bound on those round-trips, so a single request can't scan the whole catalogue when a caller has
    /// excluded almost all of it. Hitting it simply returns a short page with a cursor to carry on from.
    /// </summary>
    private const int MaxScanBatches = 20;

    /// <summary>
    /// One page of suggestions for <paramref name="type"/>, starting after rank <paramref name="afterRank"/>
    /// (null for the first page), excluding titles the owner already tracks or has dismissed.
    /// <para>
    /// Paging is a rank cursor rather than skip/limit precisely because the exclusions are applied *after* the
    /// ranked read: with a skip, every title filtered out of page 1 would shift page 2 up under the client and
    /// silently drop suggestions. Carrying the last rank examined makes each page continue exactly where the
    /// previous one stopped.
    /// </para>
    /// </summary>
    public async Task<ExploreSuggestionPageDto> GetSuggestionsAsync(
        ExploreItemType type, string ownerId, int limit, int? afterRank, CancellationToken cancellationToken = default)
    {
        var ratingSource = await ResolveRatingSourceAsync(type);
        var ranking = ExploreRankings.For(type, ratingSource);

        var excludedIds = await BuildExcludedExternalIdsAsync(type, ownerId);
        var excludedTitles = await BuildExcludedTitlesAsync(type, ownerId);

        var items = new List<ExploreSuggestionDto>();
        var cursor = afterRank ?? 0;
        var exhausted = false;

        for (var batch = 0; batch < MaxScanBatches && items.Count < limit; batch++)
        {
            var entries = await catalogueRepository.FindRankedAsync(type, ranking, cursor, ScanBatchSize);
            if (entries.Count == 0)
            {
                exhausted = true;
                break;
            }

            foreach (var entry in entries)
            {
                // advanced for every entry examined, not just every one kept, so the next page never re-reads
                // (and re-filters) a run of titles the caller already owns.
                cursor = entry.Rank;
                if (!excludedIds.Add(entry.ExternalId)) continue; // tracked, dismissed, or already on this page
                if (excludedTitles.Contains(TitleNormalizer.Normalize(entry.Title))) continue;

                items.Add(ToDto(entry, ratingSource));
                if (items.Count >= limit) break;
            }
        }

        return new ExploreSuggestionPageDto
        {
            Items = items,
            NextCursor = exhausted ? null : cursor,
            // "we haven't built this ranking yet" and "you already track all of it" are the same empty list to
            // a client but opposite messages to a user, and the first is a real state right after a fresh
            // deployment, before the first refresh pass runs. Only worth a count when the first page came back
            // with nothing at all.
            CataloguePending = afterRank is null && items.Count == 0 && await catalogueRepository.CountAsync(type, ranking) == 0
        };
    }

    /// <summary>
    /// Hides a provider title from the owner's Explore list permanently (until undone).
    /// Idempotent.
    /// </summary>
    public Task DismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.AddAsync(new ExploreDismissalModel
        {
            OwnerId = ownerId,
            ItemType = type,
            ExternalSource = ExploreRankings.DiscoverySource(type),
            ExternalId = externalId
        });

    /// <summary>
    /// Undoes a dismissal so the title can be suggested again.
    /// </summary>
    public Task UndismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.RemoveAsync(ownerId, type, ExploreRankings.DiscoverySource(type), externalId);

    /// <summary>
    /// The admin-selected primary rating source for the domain - the same setting (and the same resolver) the
    /// rest of the app ranks and displays by. An admin can additionally force movies/TV back onto TMDB; that
    /// flag is only ever read when IMDb actually won, and it cannot apply to video games (RAWG's two sources
    /// don't include IMDb). It now selects which stored rating to show, and tells the refresh pass whether
    /// IMDb values are worth fetching at all - no longer anything a request pays for.
    /// </summary>
    private async Task<string> ResolveRatingSourceAsync(ExploreItemType type)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        var source = RatingSourceCatalog.Resolve(overrides, ExploreRankings.ToReferenceItemType(type));
        return source == RatingSourceCatalog.Imdb && await appSettingRepository.GetExploreUseTmdbAsync()
            ? RatingSourceCatalog.Tmdb
            : source;
    }

    private IExploreSourceRepository SourceRepository(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => movieRepository,
        ExploreItemType.TvShow => tvShowRepository,
        ExploreItemType.VideoGame => videoGameRepository,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    // Provider ids the owner must not be suggested: what they dismissed, plus what they already track. The
    // latter is their linked reference ids resolved to those reference documents' own provider id - bounded
    // by the owner's collection size; the reference docs are the small, shared metadata ones, not tenant rows.
    private async Task<HashSet<string>> BuildExcludedExternalIdsAsync(ExploreItemType type, string ownerId)
    {
        var excluded = new HashSet<string>(
            await dismissalRepository.FindDismissedExternalIdsAsync(ownerId, type, ExploreRankings.DiscoverySource(type)));
        excluded.UnionWith(await TrackedExternalIdsAsync(type, await SourceRepository(type).FindLinkedReferenceIdsAsync(ownerId)));
        return excluded;
    }

    // The second half of "don't suggest what they already have": an item the owner typed in or imported may
    // never have been linked to a reference document at all (automatic resolution deliberately gives up when
    // a title search returns several candidates), so it has no provider id to exclude by. Matching normalized
    // titles catches those. Two genuinely different works sharing one title is possible, but hiding one
    // discovery card is a far smaller cost than repeatedly suggesting something the owner already owns.
    private async Task<HashSet<string>> BuildExcludedTitlesAsync(ExploreItemType type, string ownerId) =>
        [.. (await SourceRepository(type).FindDistinctTitlesAsync(ownerId)).Select(TitleNormalizer.Normalize)];

    private async Task<IEnumerable<string>> TrackedExternalIdsAsync(ExploreItemType type, IReadOnlyList<string> referenceIds)
    {
        var provider = ExploreRankings.DiscoverySource(type);
        return type switch
        {
            ExploreItemType.Movie => ExternalIdsOf(await movieReferenceRepository.FindByIdsAsync(referenceIds), r => r.ExternalIds, provider),
            ExploreItemType.TvShow => ExternalIdsOf(await tvShowReferenceRepository.FindByIdsAsync(referenceIds), r => r.ExternalIds, provider),
            ExploreItemType.VideoGame => ExternalIdsOf(await videoGameReferenceRepository.FindByIdsAsync(referenceIds), r => r.ExternalIds, provider),
            _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
        };
    }

    private static IEnumerable<string> ExternalIdsOf<TReference>(
        IEnumerable<TReference> references, Func<TReference, IReadOnlyDictionary<string, string>> externalIds, string provider) =>
        references.Select(r => externalIds(r).GetValueOrDefault(provider)).Where(id => !string.IsNullOrEmpty(id)).Select(id => id!);

    // the shown rating is the selected source's own stored value, and null when there isn't one - the same
    // semantics as before (a title OMDb had no rating for showed no rating), just without the per-request call.
    private static ExploreSuggestionDto ToDto(ExploreCatalogueEntryModel entry, string ratingSource)
    {
        var hasRating = entry.Ratings.TryGetValue(ratingSource, out var rating);
        return new ExploreSuggestionDto
        {
            ExternalId = entry.ExternalId,
            Title = entry.Title,
            Year = entry.Year,
            ImageUrl = entry.ImageUrl,
            Synopsis = entry.Synopsis,
            Rating = hasRating ? rating : null,
            RatingScale = hasRating ? RatingSourceCatalog.ScaleOf(ratingSource) : null
        };
    }
}
