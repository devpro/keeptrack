using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    private const string DiscogsProviderKey = "discogs";

    /// <summary>The <c>Ratings</c> map from Discogs' 0 to 5 community rating, a zero or absent value being omitted.</summary>
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
    /// The local half of "check for reference match" for albums (see <see cref="TryLinkExistingTvShowReferenceAsync"/>), against <c>album_reference</c>.
    /// A match also sets <see cref="AlbumModel.Year"/>,
    /// <see cref="AlbumModel.Artist"/> (the name from <see cref="AlbumReferenceModel.ArtistReferenceId"/>'s person) and <see cref="AlbumModel.Genre"/> to the reference's values.
    /// </summary>
    public async Task<AlbumModel> TryLinkExistingAlbumReferenceAsync(AlbumModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // one lookup without a year, since title and artist are an album's identity and a year names a pressing
        var reference = await albumReferenceRepository.FindByTitleCreatorAsync(model.Title, model.Artist);

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

        return model;
    }

    /// <summary>
    /// The admin's unlink for albums: clears the link and deletes the shared reference (see <see cref="UnlinkTvShowReferenceAsync"/>).
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
    /// Best-effort automatic match for albums (see <see cref="TryAutoResolveTvShowAsync"/>).
    /// <para>
    /// <b>An album is its title and its artist</b>, like a book: one release exists as many records, so the year breaks ties, and an artist is required (owner's rule).
    /// Several confirmed candidates are pressings of one release, Discogs returning two masters for "Thriller" by Michael Jackson,
    /// so the best is linked (see <see cref="ReferenceMatchRules.ConfirmedCreatorMatches"/>).
    /// </para>
    /// <para>
    /// Counting rows fails both ways here too: "Kid A" comes back beside "Kid A (The World Premier Broadcast)",
    /// and <c>q=Kid A&amp;artist=Radiohead&amp;year=2001</c> returns only <i>Amnesiac</i>.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveAlbumAsync(AlbumModel item)
    {
        var title = item.Title;
        var year = item.Year;
        var artist = item.Artist;

        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        // an artist is required for any automatic link, as an author is for books
        if (string.IsNullOrWhiteSpace(artist)) return;

        // a reference confirmed for this (title, artist) is the answer, asked before Discogs (see TryLinkKnownReferenceAsync)
        if (await TryLinkKnownReferenceAsync(
                () => albumReferenceRepository.FindByTitleCreatorAsync(title, artist),
                reference => WriteAlbumLinkAsync(reference, ReferenceLinkTarget.Item(item.Id!, item.OwnerId))))
        {
            return;
        }

        var candidates = await SearchForAutomaticMatchAsync(discogsClient.SearchAlbumsAsync(title, year, artist), "album", title);
        var matches = ReferenceMatchRules.ConfirmedCreatorMatches(candidates, title, artist);
        if (matches.Count == 0) return;
        await ResolveAlbumAsync(title, year, matches[0].ExternalId, ReferenceLinkTarget.Item(item.Id!, item.OwnerId));
    }

    /// <summary>
    /// "Check for reference match" for albums (see <see cref="LinkTvShowReferenceAsync"/>), the missing field being the artist,
    /// as the author is for books (<see cref="LinkBookReferenceAsync"/>).
    /// </summary>
    public async Task<AlbumModel> LinkAlbumReferenceAsync(AlbumModel model)
    {
        model = await TryLinkExistingAlbumReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        await TryAutoResolveAlbumAsync(model);
        return await albumRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>
    /// Resolves a title to a Discogs master id, upserts the reference and links the records <paramref name="target"/> names (see <see cref="ResolveTvShowAsync"/>).
    /// </summary>
    public async Task<AlbumReferenceModel> ResolveAlbumAsync(string title, int? year, string externalId, ReferenceLinkTarget target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var details = await discogsClient.GetAlbumDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Discogs master {externalId} could not be fetched.");

        // The Discogs id is checked first and is authoritative (see ResolveTvShowAsync).
        // The fallback is the album's identity, title and artist, without a year, since a document under another pressing's year is still this release and must not be duplicated.
        var existing = await albumReferenceRepository.FindByExternalIdAsync(DiscogsProviderKey, externalId)
                       ?? (details.Artist is not null ? await albumReferenceRepository.FindByTitleCreatorAsync(title, details.Artist) : null);
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
            MatchedAliases = ReferenceAliasRule.TitleAndCreator.Merge(existing?.MatchedAliases, (details.Title, details.Year ?? year, details.Artist, null), (title, year, details.Artist, null)),
            Genres = details.Genres,
            Tracks = MapTracks(details.Tracks),
            Ratings = BuildDiscogsRatings(details.Rating, details.RatingCount),
            ImageUrl = details.ImageUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await albumReferenceRepository.UpsertAsync(model);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, DiscogsProviderKey);
        await albumRepository.SetReferenceLinkAsync(target, saved.Id!, details.Title, saved.Year, details.Artist, JoinGenres(details.Genres), ratingValue, ratingScale, ratingSource);
        return saved;
    }

    /// <summary>
    /// Album equivalent of <see cref="WriteTvShowLinkAsync"/>.
    /// The artist's name is joined from <c>person_reference</c>, since an album reference stores only the id.
    /// </summary>
    private async Task WriteAlbumLinkAsync(AlbumReferenceModel reference, ReferenceLinkTarget target)
    {
        var artistName = await ResolvePersonNameAsync(reference.ArtistReferenceId);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, DiscogsProviderKey);
        await albumRepository.SetReferenceLinkAsync(target, reference.Id!, reference.Title, reference.Year,
            artistName, JoinGenres(reference.Genres), ratingValue, ratingScale, ratingSource);
    }

    /// <summary>
    /// Fetches an album reference from Discogs again, always in full, since Discogs has no "changed since" endpoint (see <see cref="RefreshTvShowReferenceAsync"/>).
    /// Unchanged for a reference without a Discogs id or one Discogs no longer holds.
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
        reference.MatchedAliases = ReferenceAliasRule.TitleAndCreator.Merge(reference.MatchedAliases, (details.Title, reference.Year, details.Artist, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await albumReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, DiscogsProviderKey);
        await albumRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    private static List<ReferenceTrackModel> MapTracks(List<DiscogsTrack> tracks) =>
        tracks.Select(t => new ReferenceTrackModel { Position = t.Position, Title = t.Title, Duration = t.Duration }).ToList();
}
