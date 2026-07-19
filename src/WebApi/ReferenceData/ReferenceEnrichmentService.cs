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
    BookReferenceClientRegistry bookReferenceClientRegistry,
    IRawgClient rawgClient,
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
    IAlbumRepository albumRepository)
{
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
    /// The dedup check compares <c>Creator</c> directly (no null/empty-string normalization needed here):
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
            if (!result.Any(m => m.Title == normalized && m.Year == year && m.Creator == normalizedCreator && m.Isbn == isbn))
            {
                result.Add(new Domain.Models.ReferenceMatchModel { Title = normalized, Year = year, Creator = normalizedCreator, Isbn = isbn });
            }
        }

        return result;
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
