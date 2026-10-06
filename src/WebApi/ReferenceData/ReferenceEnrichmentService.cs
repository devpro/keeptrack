using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves a tracked item's identity to a shared reference document and links the records a link reaches (see <see cref="ReferenceLinkTarget"/>).
/// The automatic path and the admin's manual link share it, differing only in how the provider id is picked.
/// One partial file per domain (<c>.TvShowsAndMovies.cs</c>, <c>.Books.cs</c>, <c>.VideoGames.cs</c>, <c>.Albums.cs</c>),
/// each with its TryLinkExisting, TryAutoResolve, Resolve and Refresh methods, and this file with the shared helpers.
/// <para>
/// <see cref="ReferenceAliasRule"/> decides which combinations a resolve may remember, one declaration per domain.
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
    /// The primary rating source of <paramref name="domain"/>, whose value is copied onto tenant items for display and sorting.
    /// The admin's choice (<see cref="IAppSettingRepository"/>) while on offer, else the default (<see cref="RatingSourceOptions.DefaultSource"/>).
    /// A choice not on offer is ignored but kept, so a provider change is reversible.
    /// </summary>
    public async Task<string> GetPrimaryRatingSourceAsync(ReferenceItemType domain)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        return ratingSourceOptions.Resolve(overrides, domain);
    }

    /// <summary>
    /// Applies the current primary rating source (<see cref="GetPrimaryRatingSourceAsync"/>) to every linked item of a domain,
    /// stamping the rating copy from each reference's <c>Ratings</c>.
    /// The admin recompute after a source change, with no provider call, run synchronously since the reference collection is small.
    /// <para>
    /// It first asks whether any linked item is on another source, and does nothing otherwise, the common case since the button sits beside the picker.
    /// An item never stamped counts as different, so the first recompute backfills it, with no migration script.
    /// </para>
    /// </summary>
    /// <remarks>
    /// It does not repair a value that drifted under the same source, which the periodic sync does when it refreshes a reference.
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
    /// How many references one round trip carries each way: the projected read page and its bulk write.
    /// One knob, which keeps a recompute's memory flat however large the collection or the user base.
    /// </summary>
    private const int RecomputeBatchSize = 500;

    /// <summary>
    /// The recompute loop of every domain, which differ only in the reference collection read and the tenant collection written.
    /// <para>
    /// A batch is one projected read and one bulk write: two round trips per 500 references and none per tenant item, stamped server side in each <c>UpdateMany</c>.
    /// More users mean more documents written, never more round trips, payload or memory.
    /// </para>
    /// </summary>
    private static async Task<(int ReferencesChecked, long ItemsUpdated)> RecomputeReferenceRatingsAsync(
        Func<string, Task<long>> countOnOtherSource,
        Func<string?, int, Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>>> findRatings,
        Func<IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)>, Task<long>> setRatings,
        string source)
    {
        // one count decides whether there is any work, and nothing is read or written otherwise
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

            // a short page is the last, so no query that can only come back empty
            if (batch.Count < RecomputeBatchSize) break;
        }

        return (referencesChecked, itemsUpdated);
    }

    /// <summary>
    /// Reuses a reference the local collection holds, if any, and reports whether it did: the first step of every <c>TryAutoResolve*Async</c>, before any provider.
    /// <para>
    /// A stored alias <b>is</b> the answer: someone established that this title (and year or creator) means that work.
    /// Asking a fuzzy provider again is at best slower and at worst different, and its strict confirmation could leave the item waiting for a human.
    /// </para>
    /// <para>
    /// It matters most for a film someone else already tracks, and for every row of a bulk import.
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
    /// Merges a fetch's ratings into a reference's, replacing only the sources <paramref name="providerSources"/> says this provider owns.
    /// <para>
    /// A multi-provider domain needs it: a game linked through RAWG and refreshed through IGDB keeps its <c>rawg</c> and <c>metacritic</c> values, and the reverse.
    /// Replacing the map whole would discard good scores still shown on the detail page, as <c>RebuildRatingsAsync</c> avoids for IMDb.
    /// </para>
    /// <para>
    /// A source the provider owns but no longer reports is dropped, since that is the provider answering it has no value.
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
    /// Deduplicates a credited person or group into the shared <c>person_reference</c> collection by provider id, returning the id of the document, created if needed.
    /// Shared by TV and movie cast (<see cref="ResolveCastAsync"/>, one call per member), book authors and album artists.
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
    /// A person reference's <see cref="PersonReferenceModel.Name"/> by id, the inverse of <see cref="ResolvePersonReferenceIdAsync"/>,
    /// for copying a book's author or an album's artist onto the tenant's item.
    /// </summary>
    private async Task<string?> ResolvePersonNameAsync(string? personReferenceId)
    {
        if (string.IsNullOrEmpty(personReferenceId)) return null;
        var person = await personReferenceRepository.FindByIdAsync(personReferenceId);
        return person?.Name;
    }

    /// <summary>
    /// Joins a reference's <c>Genres</c> into the single free-text <c>Genre</c> of a book or album.
    /// Null when the reference has none, so nothing is overwritten with nothing.
    /// </summary>
    private static string? JoinGenres(List<string> genres) => genres.Count > 0 ? string.Join(", ", genres) : null;
}
