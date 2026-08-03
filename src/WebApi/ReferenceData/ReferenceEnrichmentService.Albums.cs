using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    private const string DiscogsProviderKey = "discogs";

    /// <summary>Builds the reference <c>Ratings</c> map from Discogs' 0-5 community rating; a 0/absent value is omitted, not stored as a real zero.</summary>
    private static Dictionary<string, ReferenceRatingModel> BuildDiscogsRatings(double? rating, int? ratingCount)
    {
        var ratings = new Dictionary<string, ReferenceRatingModel>();
        if (rating is > 0)
        {
            ratings[DiscogsProviderKey] = new ReferenceRatingModel { Value = rating.Value, Scale = 5, Count = ratingCount };
        }
        return ratings;
    }

    /// <summary>
    /// User-triggered "check for reference match" for albums - see
    /// <see cref="TryLinkExistingTvShowReferenceAsync"/> for the full rationale (this is the same local-only,
    /// no-HTTP-call lookup, just against <c>album_reference</c>). A successful match also sets
    /// <see cref="AlbumModel.Year"/>, <see cref="AlbumModel.Artist"/> and <see cref="AlbumModel.Genre"/> to the
    /// reference's canonical values - the artist's name is joined from <see cref="PersonReferenceModel"/> via
    /// <see cref="AlbumReferenceModel.ArtistReferenceId"/>, and Genre from <see cref="AlbumReferenceModel.Genres"/>
    /// (joined into the same single free-text field the tenant can otherwise edit by hand).
    /// </summary>
    public async Task<AlbumModel> TryLinkExistingAlbumReferenceAsync(AlbumModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // see TryLinkExistingTvShowReferenceAsync's own comment - the title-only fallback must not run when
        // the tenant has a specific year that simply has no confirmed alias
        var reference = await albumReferenceRepository.FindByTitleYearAsync(model.Title, model.Year, model.Artist);
        if (reference is null && model.Year is null)
        {
            reference = await albumReferenceRepository.FindByTitleAsync(model.Title, model.Artist);
        }

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                model.ReferenceRating = null;
                model.ReferenceRatingScale = null;
                model.ReferenceRatingSource = null;
                await albumRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;
        var artistName = await ResolvePersonNameAsync(reference.ArtistReferenceId);
        var genre = JoinGenres(reference.Genres);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, DiscogsProviderKey);

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        if (!string.IsNullOrEmpty(artistName)) model.Artist = artistName;
        if (genre is not null) model.Genre = genre;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await albumRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await albumRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, artistName, genre, ratingValue, ratingScale, ratingSource);

        return model;
    }

    /// <summary>
    /// Admin-triggered "unlink" for albums - see <see cref="UnlinkTvShowReferenceAsync"/> for the full
    /// rationale (clears the tenant's link and permanently deletes the shared reference document, rather
    /// than only detaching this one item).
    /// </summary>
    public async Task<AlbumModel> UnlinkAlbumReferenceAsync(AlbumModel model)
    {
        var referenceId = model.ReferenceId;
        model.ReferenceId = string.Empty;
        model.ReferenceRating = null;
        model.ReferenceRatingScale = null;
        model.ReferenceRatingSource = null;
        await albumRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await albumReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for albums - see <see cref="TryAutoResolveTvShowAsync"/>. Passing
    /// <paramref name="artist"/> narrows the Discogs search considerably - without it, a common album
    /// title easily returns more than one candidate and the match is correctly left for the admin queue.
    /// </summary>
    public async Task TryAutoResolveAlbumAsync(string title, int? year, string? artist = null)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        var candidates = await discogsClient.SearchAlbumsAsync(title, year, artist);
        if (candidates.Count != 1) return;
        await ResolveAlbumAsync(title, year, candidates[0].ExternalId);
    }

    /// <summary>
    /// Resolves a title+year to a specific Discogs master id, upserts the reference document, and
    /// propagates the link - see <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<AlbumReferenceModel> ResolveAlbumAsync(string title, int? year, string externalId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var details = await discogsClient.GetAlbumDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Discogs master {externalId} could not be fetched.");

        // see ResolveTvShowAsync's own comment - the title-only fallback (which reuses existing.Id for the
        // upsert) must not run when year is known but simply unconfirmed yet, or it risks overwriting an
        // unrelated same-titled reference document instead of just linking wrong
        var existing = await albumReferenceRepository.FindByExternalIdAsync(DiscogsProviderKey, externalId)
                       ?? (details.Artist is not null ? await albumReferenceRepository.FindByTitleYearAsync(title, year, details.Artist) : null);
        if (existing is null && year is null && details.Artist is not null)
        {
            existing = await albumReferenceRepository.FindByTitleAsync(title, details.Artist);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds[DiscogsProviderKey] = externalId;

        var artistReferenceId = !string.IsNullOrEmpty(details.ArtistExternalId)
            ? await ResolvePersonReferenceIdAsync(DiscogsProviderKey, details.ArtistExternalId, details.Artist ?? "Unknown", null)
            : existing?.ArtistReferenceId;

        var model = new AlbumReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            ArtistReferenceId = artistReferenceId,
            ExternalIds = externalIds,
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, details.Artist, null), (title, year, details.Artist, null)),
            Genres = details.Genres,
            Tracks = MapTracks(details.Tracks),
            Ratings = BuildDiscogsRatings(details.Rating, details.RatingCount),
            ImageUrl = details.ImageUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await albumReferenceRepository.UpsertAsync(model);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, DiscogsProviderKey);
        await albumRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, details.Artist, JoinGenres(details.Genres), ratingValue, ratingScale, ratingSource);
        return saved;
    }

    /// <summary>
    /// Re-fetches an album reference from Discogs, always doing a full re-fetch when called (unlike TMDB,
    /// Discogs exposes no per-id "has this changed" endpoint) - see <see cref="RefreshTvShowReferenceAsync"/>
    /// for the shared staleness-cutoff mechanism this is invoked from. A no-op (returns unchanged) for a
    /// reference with no Discogs id or that Discogs no longer has details for.
    /// </summary>
    public async Task<(AlbumReferenceModel Model, bool DataChanged)> RefreshAlbumReferenceAsync(AlbumReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var externalId = reference.ExternalIds.GetValueOrDefault(DiscogsProviderKey);
        if (string.IsNullOrEmpty(externalId)) return (reference, false);

        var details = await discogsClient.GetAlbumDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        if (!string.IsNullOrEmpty(details.ArtistExternalId))
        {
            reference.ArtistReferenceId = await ResolvePersonReferenceIdAsync(DiscogsProviderKey, details.ArtistExternalId, details.Artist ?? "Unknown", null);
        }
        reference.Genres = details.Genres;
        reference.Tracks = MapTracks(details.Tracks);
        reference.Ratings = BuildDiscogsRatings(details.Rating, details.RatingCount);
        reference.ImageUrl = details.ImageUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, details.Artist, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await albumReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, DiscogsProviderKey);
        await albumRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    private static List<ReferenceTrackModel> MapTracks(List<DiscogsTrack> tracks) =>
        tracks.Select(t => new ReferenceTrackModel { Position = t.Position, Title = t.Title, Duration = t.Duration }).ToList();
}
