using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Text.Json;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Controllers;
using Keeptrack.WebApi.Jobs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Lets an admin/maintainer resolve titles the automatic match couldn't confidently handle (ambiguous or zero results),
/// across every reference-backed domain (TV shows, movies, books, video games, albums).
/// Not per-tenant CRUD, so this doesn't extend <see cref="Controllers.DataCrudControllerBase{TDto,TModel}"/>.
/// </summary>
[ApiController]
[Authorize(Policy = "AdminOnly")]
[Route("api/reference-data")]
public class ReferenceDataAdminController(
    ITvShowRepository tvShowRepository,
    IMovieRepository movieRepository,
    IBookRepository bookRepository,
    IVideoGameRepository videoGameRepository,
    IAlbumRepository albumRepository,
    ITmdbClient tmdbClient,
    BookReferenceClientRegistry bookReferenceClientRegistry,
    IRawgClient rawgClient,
    IDiscogsClient discogsClient,
    ReferenceEnrichmentService enrichmentService,
    JobStore<ReferenceSyncStage, ReferenceSyncResultDto> syncJobStore,
    IServiceScopeFactory scopeFactory,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IPersonReferenceRepository personReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IAlbumReferenceRepository albumReferenceRepository) : ControllerBase
{
    private const string TvShowEntryName = "tvshow_reference.json";
    private const string MovieEntryName = "movie_reference.json";
    private const string PersonEntryName = "person_reference.json";
    private const string BookEntryName = "book_reference.json";
    private const string VideoGameEntryName = "videogame_reference.json";
    private const string AlbumEntryName = "album_reference.json";

    /// <summary>
    /// Every reference document as a zip, so an admin can seed a fresh environment's reference data without re-earning every match one search at a time.
    /// </summary>
    [HttpGet("export")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Export()
    {
        var tvShows = await tvShowReferenceRepository.FindAllAsync();
        var movies = await movieReferenceRepository.FindAllAsync();
        var people = await personReferenceRepository.FindAllAsync();
        var books = await bookReferenceRepository.FindAllAsync();
        var videoGames = await videoGameReferenceRepository.FindAllAsync();
        var albums = await albumReferenceRepository.FindAllAsync();

        var buffer = new MemoryStream();
        await using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            await WriteJsonEntryAsync(archive, TvShowEntryName, tvShows);
            await WriteJsonEntryAsync(archive, MovieEntryName, movies);
            await WriteJsonEntryAsync(archive, PersonEntryName, people);
            await WriteJsonEntryAsync(archive, BookEntryName, books);
            await WriteJsonEntryAsync(archive, VideoGameEntryName, videoGames);
            await WriteJsonEntryAsync(archive, AlbumEntryName, albums);
        }

        buffer.Position = 0;
        return File(buffer, "application/zip", "keeptrack-reference-data.zip");
    }

    /// <summary>
    /// Idempotent (upsert-by-id) re-import of a previously exported zip -
    /// re-running the same import twice is a no-op the second time, since every document already carries the id it was exported with.
    /// </summary>
    [HttpPost("import")]
    [RequestSizeLimit(50_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (50 MB), deliberately above Sonar's 8 MB default: " +
                        "a full reference-data export (six collections of episode guides, cast, aliases) grows past 8 MB, and the endpoint is admin-only.")]
    public async Task<ActionResult<ReferenceDataImportResultDto>> Import(IFormFile file)
    {
        if (file.Length == 0) return BadRequest();

        await using var uploadStream = file.OpenReadStream();
        await using var archive = new ZipArchive(uploadStream, ZipArchiveMode.Read);

        var tvShowCount = 0;
        var movieCount = 0;
        var personCount = 0;
        var bookCount = 0;
        var videoGameCount = 0;
        var albumCount = 0;

        foreach (var show in await ReadJsonEntryAsync<TvShowReferenceModel>(archive, TvShowEntryName))
        {
            await tvShowReferenceRepository.UpsertAsync(show);
            tvShowCount++;
        }

        foreach (var movie in await ReadJsonEntryAsync<MovieReferenceModel>(archive, MovieEntryName))
        {
            await movieReferenceRepository.UpsertAsync(movie);
            movieCount++;
        }

        foreach (var person in await ReadJsonEntryAsync<PersonReferenceModel>(archive, PersonEntryName))
        {
            await personReferenceRepository.UpsertAsync(person);
            personCount++;
        }

        foreach (var book in await ReadJsonEntryAsync<BookReferenceModel>(archive, BookEntryName))
        {
            await bookReferenceRepository.UpsertAsync(book);
            bookCount++;
        }

        foreach (var videoGame in await ReadJsonEntryAsync<VideoGameReferenceModel>(archive, VideoGameEntryName))
        {
            await videoGameReferenceRepository.UpsertAsync(videoGame);
            videoGameCount++;
        }

        foreach (var album in await ReadJsonEntryAsync<AlbumReferenceModel>(archive, AlbumEntryName))
        {
            await albumReferenceRepository.UpsertAsync(album);
            albumCount++;
        }

        return Ok(new ReferenceDataImportResultDto
        {
            TvShowCount = tvShowCount,
            MovieCount = movieCount,
            PersonCount = personCount,
            BookCount = bookCount,
            VideoGameCount = videoGameCount,
            AlbumCount = albumCount
        });
    }

    private static async Task WriteJsonEntryAsync<T>(ZipArchive archive, string entryName, T value)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync();
        await JsonSerializer.SerializeAsync(entryStream, value);
    }

    private static async Task<List<T>> ReadJsonEntryAsync<T>(ZipArchive archive, string entryName)
    {
        var entry = archive.GetEntry(entryName);
        if (entry is null) return [];

        await using var entryStream = await entry.OpenAsync();
        return await JsonSerializer.DeserializeAsync<List<T>>(entryStream) ?? [];
    }

    /// <summary>
    /// Starts an immediate re-check of every reference document, regardless of how recently it was last
    /// enriched - the same logic the periodic background sync runs on a schedule (see
    /// <see cref="ReferenceSyncBackgroundService"/>), just triggered on demand instead of waiting. Runs in
    /// the background; poll <see cref="GetSyncStatus"/> with the returned job id for progress - a full
    /// re-check across five domains can easily exceed a single request/response's own timeout.
    /// </summary>
    [HttpPost("sync-now")]
    [ProducesResponseType(202)]
    public async Task<ActionResult<ReferenceSyncJobDto>> SyncNow()
    {
        var jobId = await syncJobStore.CreateAsync(this.GetUserId(), ReferenceSyncStage.SyncingTvShows);

        _ = RunSyncJobAsync(jobId);

        return Accepted(new ReferenceSyncJobDto { JobId = jobId });
    }

    /// <summary>
    /// Current status of a previously started sync job.
    /// </summary>
    [HttpGet("sync-now/{jobId:guid}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<ReferenceSyncJobStatusDto>> GetSyncStatus(Guid jobId)
    {
        var status = await syncJobStore.GetStatusAsync(jobId, this.GetUserId());
        if (status is null) return NotFound();

        return Ok(new ReferenceSyncJobStatusDto { Stage = status.Value.Stage, Result = status.Value.Result, ErrorMessage = status.Value.ErrorMessage });
    }

    /// <summary>
    /// Runs the sync on a background task using its own DI scope - the request that started it has
    /// already completed by the time this runs, so it can't reuse the request's scoped services
    /// (neither <see cref="ReferenceSyncService"/> nor the request's own JobStore instance).
    /// </summary>
    private async Task RunSyncJobAsync(Guid jobId)
    {
        using var scope = scopeFactory.CreateScope();
        var scopedSyncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
        var scopedJobStore = scope.ServiceProvider.GetRequiredService<JobStore<ReferenceSyncStage, ReferenceSyncResultDto>>();

        try
        {
            var result = await scopedSyncService.SyncStaleReferencesAsync(TimeSpan.Zero, stage => scopedJobStore.UpdateStageAsync(jobId, stage));
            await scopedJobStore.CompleteAsync(jobId, ReferenceSyncStage.Completed, result);
        }
        catch (Exception ex)
        {
            await scopedJobStore.FailAsync(jobId, ReferenceSyncStage.Failed, ex.Message);
        }
    }

    /// <summary>
    /// Every registered book provider an admin can search/link with - Book is the one reference domain with
    /// more than one (TMDB/RAWG/Discogs each have exactly one, so no equivalent listing endpoint exists for them).
    /// </summary>
    [HttpGet("book-providers")]
    [ProducesResponseType(200)]
    public ActionResult<List<BookProviderDto>> GetBookProviders() =>
        Ok(bookReferenceClientRegistry.All.Select(c => new BookProviderDto { Key = c.ProviderKey, DisplayName = c.DisplayName }).ToList());

    /// <summary>
    /// Distinct (title, year) pairs, across every tenant, still missing a reference-data link. Book is
    /// handled separately since it's the only domain whose <c>FindDistinctUnresolvedTitleYearsAsync</c>
    /// also surfaces a prefill <c>Isbn</c> (see <see cref="IBookRepository.FindDistinctUnresolvedTitleYearsAsync"/>) -
    /// forcing that onto the other four's shared tuple shape for one field only they'd never populate
    /// wasn't worth it.
    /// </summary>
    [HttpGet("unresolved")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<UnresolvedReferenceDto>>> GetUnresolved([FromQuery] ReferenceItemType type)
    {
        if (type == ReferenceItemType.Book)
        {
            var bookPairs = await bookRepository.FindDistinctUnresolvedTitleYearsAsync();
            return Ok(bookPairs.Select(p => new UnresolvedReferenceDto { Type = type, Title = p.Title, Year = p.Year, Creator = p.Creator, Isbn = p.Isbn }).ToList());
        }

        var pairs = type switch
        {
            ReferenceItemType.TvShow => await tvShowRepository.FindDistinctUnresolvedTitleYearsAsync(),
            ReferenceItemType.Movie => await movieRepository.FindDistinctUnresolvedTitleYearsAsync(),
            ReferenceItemType.VideoGame => await videoGameRepository.FindDistinctUnresolvedTitleYearsAsync(),
            ReferenceItemType.Album => await albumRepository.FindDistinctUnresolvedTitleYearsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

        return Ok(pairs.Select(p => new UnresolvedReferenceDto { Type = type, Title = p.Title, Year = p.Year, Creator = p.Creator }).ToList());
    }

    /// <summary>
    /// How many search candidates get enriched with a poster and top cast names (TV/movie only) - bounds
    /// the extra per-candidate credits calls to a small, admin-facing action, not the full result page.
    /// </summary>
    private const int MaxEnrichedCandidates = 5;

    private const int MaxCastNamesPerCandidate = 3;

    /// <summary>
    /// Live external-provider search, for an admin to pick the right candidate for an unresolved title.
    /// TV show/movie candidates are additionally enriched with top-billed cast names to help tell apart near-identical results
    /// (remakes, regional variants, sequels sharing a title).
    /// </summary>
    /// <summary>
    /// <paramref name="creator"/> is the book's author or the album's artist, when the caller has one -
    /// passed straight through to the provider's own author/artist search field
    /// (see <see cref="IBookReferenceClient.SearchBooksAsync"/>/<see cref="IDiscogsClient.SearchAlbumsAsync"/>),
    /// since a common title alone often returns many unrelated candidates.
    /// Ignored for TV shows/movies/video games, which have no equivalent single-name creator field on this endpoint.
    /// <paramref name="provider"/> selects which registered book provider to search with (see
    /// <see cref="GetBookProviders"/>); ignored for every other type. Null falls back to the deployment default.
    /// <paramref name="isbn"/> is Book-only - an exact identifier, only actually used by
    /// <see cref="GoogleBooksClient"/> (see its own doc comment on <see cref="IBookReferenceClient.SearchBooksAsync"/>).
    /// </summary>
    [HttpGet("search")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<List<ReferenceSearchResultDto>>> Search([FromQuery] ReferenceItemType type, [FromQuery] string title, [FromQuery] int? year,
        [FromQuery] string? creator = null, [FromQuery] string? provider = null, [FromQuery] string? isbn = null)
    {
        // never hit a provider with an empty title - mapped to a 400 by ApiExceptionFilterAttribute
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        switch (type)
        {
            case ReferenceItemType.TvShow:
            case ReferenceItemType.Movie:
                return Ok(await SearchTvShowOrMovieAsync(type, title, year));
            case ReferenceItemType.Book:
                var books = await bookReferenceClientRegistry.Resolve(provider).SearchBooksAsync(title, year, creator, isbn);
                return Ok(books.Take(MaxEnrichedCandidates)
                    .Select(r => new ReferenceSearchResultDto
                    {
                        ExternalId = r.ExternalId,
                        Title = r.Title,
                        Year = r.Year,
                        Creator = r.Author,
                        ImageUrl = r.ImageUrl
                    })
                    .ToList());
            case ReferenceItemType.VideoGame:
                var games = await rawgClient.SearchGamesAsync(title, year);
                return Ok(games.Take(MaxEnrichedCandidates)
                    .Select(r => new ReferenceSearchResultDto { ExternalId = r.ExternalId, Title = r.Title, Year = r.Year, ImageUrl = r.ImageUrl })
                    .ToList());
            case ReferenceItemType.Album:
                var albums = await discogsClient.SearchAlbumsAsync(title, year, creator);
                return Ok(albums.Take(MaxEnrichedCandidates)
                    .Select(r => new ReferenceSearchResultDto
                    {
                        ExternalId = r.ExternalId,
                        Title = r.Title,
                        Year = r.Year,
                        Creator = r.Artist,
                        ImageUrl = r.ImageUrl
                    })
                    .ToList());
            default:
                throw new ArgumentOutOfRangeException(nameof(type));
        }
    }

    private async Task<List<ReferenceSearchResultDto>> SearchTvShowOrMovieAsync(ReferenceItemType type, string title, int? year)
    {
        var results = type == ReferenceItemType.TvShow
            ? await tmdbClient.SearchTvShowAsync(title, year)
            : await tmdbClient.SearchMovieAsync(title, year);

        var dtos = new List<ReferenceSearchResultDto>();
        foreach (var result in results.Take(MaxEnrichedCandidates))
        {
            var cast = type == ReferenceItemType.TvShow
                ? await tmdbClient.GetTvShowCastAsync(result.TmdbId)
                : await tmdbClient.GetMovieCastAsync(result.TmdbId);

            dtos.Add(new ReferenceSearchResultDto
            {
                ExternalId = result.TmdbId,
                Title = result.Title,
                Year = result.Year,
                Synopsis = result.Synopsis,
                ImageUrl = result.PosterUrl,
                TopCastNames = cast.OrderBy(c => c.Order).Take(MaxCastNamesPerCandidate).Select(c => c.Name).ToList()
            });
        }

        return dtos;
    }

    /// <summary>
    /// Links every tenant's (Title, Year) match to the chosen external provider id and fetches its full details.
    /// </summary>
    [HttpPost("link")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Link([FromBody] LinkReferenceRequestDto request)
    {
        switch (request.Type)
        {
            case ReferenceItemType.TvShow:
                await enrichmentService.ResolveTvShowAsync(request.Title, request.Year, request.ExternalId);
                break;
            case ReferenceItemType.Movie:
                await enrichmentService.ResolveMovieAsync(request.Title, request.Year, request.ExternalId);
                break;
            case ReferenceItemType.Book:
                await enrichmentService.ResolveBookAsync(request.Title, request.Year, request.ExternalId, request.Provider, request.Isbn);
                break;
            case ReferenceItemType.VideoGame:
                await enrichmentService.ResolveVideoGameAsync(request.Title, request.Year, request.ExternalId);
                break;
            case ReferenceItemType.Album:
                await enrichmentService.ResolveAlbumAsync(request.Title, request.Year, request.ExternalId);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(request));
        }

        return NoContent();
    }
}
