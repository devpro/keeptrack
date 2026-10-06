using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Explore: suggests acclaimed titles the caller does not track and has not dismissed.
/// <para>
/// It reads the stored ranking (<c>explore_catalogue</c>, rewritten weekly by <see cref="ExploreCatalogueRefreshService"/>) rather than calling a provider.
/// The ranking is the same for every user, only the exclusions being per caller, and a stored, indexed ranking can be paged as deep as it goes.
/// </para>
/// <para>
/// The ordering follows the admin's primary rating source, choosing which stored ordering to read.
/// IMDb values are the refresh's business, so at read time they are one more entry of the ratings map.
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
    IExploreDismissalRepository dismissalRepository,
    ExploreRankings exploreRankings,
    RatingSourceOptions ratingSourceOptions)
{
    /// <summary>
    /// How many ranked entries to read per round trip while filling a page, more than a page since most survive the exclusions.
    /// </summary>
    private const int ScanBatchSize = 100;

    /// <summary>
    /// Upper bound of those round trips, so one request never scans the whole catalogue for a caller who excluded almost all of it.
    /// Reaching it returns a short page with a cursor to continue from.
    /// </summary>
    private const int MaxScanBatches = 20;

    /// <summary>
    /// One page of suggestions for <paramref name="type"/> after rank <paramref name="afterRank"/> (null for the first page), without titles the owner tracks or dismissed.
    /// <para>
    /// A rank cursor rather than skip and limit, since the exclusions apply after the ranked read, and a skip would shift later pages and drop suggestions.
    /// </para>
    /// </summary>
    public async Task<ExploreSuggestionPageDto> GetSuggestionsAsync(
        ExploreItemType type, string ownerId, int limit, int? afterRank, CancellationToken cancellationToken = default)
    {
        var ratingSource = await ResolveRatingSourceAsync(type);
        var ranking = exploreRankings.For(type, ratingSource);

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
                // advanced for every entry examined, so the next page never reads again a run of titles the caller owns
                cursor = entry.Rank;
                if (!excludedIds.Add(entry.ExternalId)) continue; // tracked, dismissed or already on this page
                if (excludedTitles.Contains(TitleNormalizer.NormalizeLoose(entry.Title))) continue;

                items.Add(ToDto(entry, ratingSource, exploreRankings.DiscoverySource(type)));
                if (items.Count >= limit) break;
            }
        }

        return new ExploreSuggestionPageDto
        {
            Items = items,
            NextCursor = exhausted ? null : cursor,
            // "not built yet" and "everything tracked" are the same empty list but opposite messages, the first real before a new deployment's first refresh.
            // Counted only when the first page is empty.
            CataloguePending = afterRank is null && items.Count == 0 && await catalogueRepository.CountAsync(type, ranking) == 0
        };
    }

    /// <summary>
    /// Hides a title from the owner's Explore list until undone, idempotently.
    /// </summary>
    public Task DismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.AddAsync(new ExploreDismissalModel
        {
            OwnerId = ownerId,
            ItemType = type,
            ExternalSource = exploreRankings.DiscoverySource(type),
            ExternalId = externalId
        });

    /// <summary>
    /// Undoes a dismissal so the title can be suggested again.
    /// </summary>
    public Task UndismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.RemoveAsync(ownerId, type, exploreRankings.DiscoverySource(type), externalId);

    /// <summary>
    /// The admin's primary rating source for the domain, through the same resolver as the rest of the app.
    /// An admin can force movies and TV back onto TMDB, a flag read only when IMDb won, so it never reaches video games.
    /// It picks the stored rating shown, and tells the refresh whether IMDb values are worth fetching.
    /// <para>
    /// <see cref="ExploreRankings.DisplaySource"/> then turns a source the catalogue cannot carry into the ranking's own rather than blanking every card.
    /// </para>
    /// </summary>
    private async Task<string> ResolveRatingSourceAsync(ExploreItemType type)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        var source = ratingSourceOptions.Resolve(overrides, ExploreRankings.ToReferenceItemType(type));
        if (source == RatingSourceCatalog.Imdb && await appSettingRepository.GetExploreUseTmdbAsync())
        {
            source = RatingSourceCatalog.Tmdb;
        }

        return exploreRankings.DisplaySource(type, source);
    }

    private IExploreSourceRepository SourceRepository(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => movieRepository,
        ExploreItemType.TvShow => tvShowRepository,
        ExploreItemType.VideoGame => videoGameRepository,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    // Provider ids never suggested to the owner: those dismissed, plus those tracked, the linked references resolved to their provider ids.
    private async Task<HashSet<string>> BuildExcludedExternalIdsAsync(ExploreItemType type, string ownerId)
    {
        var excluded = new HashSet<string>(
            await dismissalRepository.FindDismissedExternalIdsAsync(ownerId, type, exploreRankings.DiscoverySource(type)));
        excluded.UnionWith(await TrackedExternalIdsAsync(type, await SourceRepository(type).FindLinkedReferenceIdsAsync(ownerId)));
        return excluded;
    }

    // The second half of the exclusion: an item never linked has no provider id to exclude by, so normalized titles catch it.
    // Two works can share a title, but hiding one card costs far less than suggesting what the owner has.
    //
    // Matched loosely (TitleNormalizer.NormalizeLoose), since a linked item carries the linking provider's title and the catalogue the discovery provider's, spelled differently ("Mass Effect: Legendary Edition", "Mass Effect Legendary Edition").
    // Exact equality would miss the very references that could not adopt the discovery provider's id, failing both halves on the same games.
    private async Task<HashSet<string>> BuildExcludedTitlesAsync(ExploreItemType type, string ownerId) =>
        [.. (await SourceRepository(type).FindDistinctTitlesAsync(ownerId)).Select(TitleNormalizer.NormalizeLoose)];

    // projected, reading only external_ids, since a show reference embeds its whole episode guide and the exclusion needs one string
    private async Task<IReadOnlyList<string>> TrackedExternalIdsAsync(ExploreItemType type, IReadOnlyList<string> referenceIds)
    {
        var provider = exploreRankings.DiscoverySource(type);
        return type switch
        {
            ExploreItemType.Movie => await movieReferenceRepository.FindExternalIdsAsync(referenceIds, provider),
            ExploreItemType.TvShow => await tvShowReferenceRepository.FindExternalIdsAsync(referenceIds, provider),
            ExploreItemType.VideoGame => await videoGameReferenceRepository.FindExternalIdsAsync(referenceIds, provider),
            _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
        };
    }

    // the shown rating is the selected source's stored value, null when there is none
    private ExploreSuggestionDto ToDto(ExploreCatalogueEntryModel entry, string ratingSource, string discoverySource)
    {
        var hasRating = entry.Ratings.TryGetValue(ratingSource, out var rating);
        var linkSource = LinkSource(entry, ratingSource, discoverySource);
        return new ExploreSuggestionDto
        {
            ExternalId = entry.ExternalId,
            Title = entry.Title,
            Year = entry.Year,
            ImageUrl = entry.ImageUrl,
            Synopsis = entry.Synopsis,
            Rating = hasRating ? rating : null,
            RatingScale = hasRating ? RatingSourceCatalog.ScaleOf(ratingSource) : null,
            ProviderUrl = linkSource is null ? null : entry.WebUrls[linkSource],
            ProviderName = linkSource is null ? null : exploreRankings.SiteName(linkSource)
        };
    }

    // The page a card links to: the site whose number it shows (an IMDb rating opens IMDb), else the discovery provider's page, which the refresh writes from the listing.
    // Null when neither is stored, and the card is then not a link, never a dead one.
    private static string? LinkSource(ExploreCatalogueEntryModel entry, string ratingSource, string discoverySource)
    {
        if (entry.WebUrls.ContainsKey(ratingSource)) return ratingSource;
        return entry.WebUrls.ContainsKey(discoverySource) ? discoverySource : null;
    }
}
