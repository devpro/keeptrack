using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Text.Json;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
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
    ReferenceClientRegistry<IBookReferenceClient> bookReferenceClientRegistry,
    ReferenceClientRegistry<IVideoGameReferenceClient> videoGameReferenceClientRegistry,
    IDiscogsClient discogsClient,
    ReferenceEnrichmentService enrichmentService,
    JobStore<ReferenceSyncStage, ReferenceSyncResultDto> syncJobStore,
    JobStore<ReferenceDataImportStage, ReferenceDataImportResultDto> importJobStore,
    IServiceScopeFactory scopeFactory,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IPersonReferenceRepository personReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IAlbumReferenceRepository albumReferenceRepository,
    IAppSettingRepository appSettingRepository,
    IHostApplicationLifetime lifetime,
    ILogger<ReferenceDataAdminController> logger) : ControllerBase
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
    /// Re-import of a previously exported zip, into whatever the target database already holds.
    /// Every document is matched by its <b>provider id</b> (TMDB, IGDB, Google Books, Discogs...), never by the <c>_id</c> it was exported with -
    /// see <see cref="ReferenceDataImportService"/> for why that distinction is the whole feature, and for what a match merges rather than replaces.
    /// Idempotent either way: re-running the same import updates the same documents in place a second time.
    /// <para>
    /// Runs in the background; poll <see cref="GetImportStatus"/> with the returned job id for progress. A real
    /// export is tens of thousands of documents (people alone run to five figures), each one a write, so this
    /// comfortably outlives a single request/response - as a blocking call it died on the *client's* default
    /// 100s <c>HttpClient.Timeout</c> while the server kept importing, reporting a failure for work that was
    /// still running and would go on to succeed.
    /// </para>
    /// </summary>
    [HttpPost("import")]
    [RequestSizeLimit(50_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(202)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (50 MB), deliberately above Sonar's 8 MB default: " +
                        "a full reference-data export (six collections of episode guides, cast, aliases) grows past 8 MB, and the endpoint is admin-only.")]
    public async Task<ActionResult<ReferenceDataImportJobDto>> Import(IFormFile file)
    {
        if (file.Length == 0) return BadRequest();

        // buffered up front: IFormFile's stream isn't valid once this request finishes, but the import itself
        // runs in the background after we respond
        var buffer = new MemoryStream();
        await using (var uploadStream = file.OpenReadStream())
        {
            await uploadStream.CopyToAsync(buffer);
        }

        buffer.Position = 0;
        var jobId = await importJobStore.CreateAsync(this.GetUserId(), ReferenceDataImportStage.Parsing);

        _ = RunImportJobAsync(jobId, buffer);

        return Accepted(new ReferenceDataImportJobDto { JobId = jobId });
    }

    /// <summary>
    /// Current status of a previously started import job.
    /// </summary>
    [HttpGet("import/{jobId:guid}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<ReferenceDataImportJobStatusDto>> GetImportStatus(Guid jobId)
    {
        var status = await importJobStore.GetStatusAsync(jobId, this.GetUserId());
        if (status is null) return NotFound();

        return Ok(new ReferenceDataImportJobStatusDto { Stage = status.Value.Stage, Result = status.Value.Result, ErrorMessage = status.Value.ErrorMessage });
    }

    /// <summary>
    /// Runs the import on a background task using its own DI scope - the request that started it has already
    /// completed by the time this runs, so none of the request's scoped services (the six repositories, its own
    /// JobStore) are still usable.
    /// <para>
    /// It runs on <see cref="IHostApplicationLifetime.ApplicationStopping"/> for the same reason
    /// <see cref="RunSyncJobAsync"/> does: a shutdown mid-import would otherwise leave it writing against a
    /// disposed Mongo client, including the final job-store write that would leave the job reading "Running"
    /// forever. Stopping partway is safe here - the import is idempotent, so re-running the same zip picks up
    /// what didn't land and updates what did.
    /// </para>
    /// </summary>
    private async Task RunImportJobAsync(Guid jobId, MemoryStream buffer)
    {
        var cancellationToken = lifetime.ApplicationStopping;
        await using (buffer)
        {
            using var scope = scopeFactory.CreateScope();
            var scopedJobStore = scope.ServiceProvider.GetRequiredService<JobStore<ReferenceDataImportStage, ReferenceDataImportResultDto>>();

            try
            {
                var payload = await ReadPayloadAsync(buffer);
                var summary = await ReferenceDataImportService.ImportAsync(
                    payload,
                    new ReferenceRepositorySet(
                        scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>(),
                        scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>(),
                        scope.ServiceProvider.GetRequiredService<IPersonReferenceRepository>(),
                        scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>(),
                        scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>(),
                        scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>()),
                    collection => scopedJobStore.UpdateStageAsync(jobId, StageOf(collection)),
                    cancellationToken);

                foreach (var skipped in summary.SkippedExternalIds)
                {
                    // reported in the result too, but logged so the collision leaves a server-side trail: it means the
                    // target holds two reference documents for one work, which the import deliberately won't merge on its own.
                    logger.LogWarning("Reference-data import skipped external id {ExternalId}: another document in this database already claims it.", skipped);
                }

                await scopedJobStore.CompleteAsync(jobId, ReferenceDataImportStage.Completed, new ReferenceDataImportResultDto
                {
                    TvShows = ToDto(summary.TvShows),
                    Movies = ToDto(summary.Movies),
                    People = ToDto(summary.People),
                    Books = ToDto(summary.Books),
                    VideoGames = ToDto(summary.VideoGames),
                    Albums = ToDto(summary.Albums),
                    SkippedExternalIds = summary.SkippedExternalIds
                });
            }
            catch (OperationCanceledException)
            {
                // the API is going down, so this is neither a success nor a fault to investigate - just say so
                // plainly and stop. Best-effort: the job store may already be unusable at this point.
                try
                {
                    await scopedJobStore.FailAsync(jobId, ReferenceDataImportStage.Failed,
                        "The API shut down before the import finished. Import the same file again once it is back up - it will pick up where this one stopped.");
                }
                catch (Exception writeFailure)
                {
                    logger.LogWarning(writeFailure, "Could not record that import job {JobId} was interrupted by shutdown.", jobId);
                }
            }
            catch (Exception ex)
            {
                await scopedJobStore.FailAsync(jobId, ReferenceDataImportStage.Failed, ex.Message);
            }
        }
    }

    private static async Task<ReferenceDataImportPayload> ReadPayloadAsync(Stream zipStream)
    {
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

        return new ReferenceDataImportPayload
        {
            TvShows = await ReadJsonEntryAsync<TvShowReferenceModel>(archive, TvShowEntryName),
            Movies = await ReadJsonEntryAsync<MovieReferenceModel>(archive, MovieEntryName),
            People = await ReadJsonEntryAsync<PersonReferenceModel>(archive, PersonEntryName),
            Books = await ReadJsonEntryAsync<BookReferenceModel>(archive, BookEntryName),
            VideoGames = await ReadJsonEntryAsync<VideoGameReferenceModel>(archive, VideoGameEntryName),
            Albums = await ReadJsonEntryAsync<AlbumReferenceModel>(archive, AlbumEntryName)
        };
    }

    /// <summary>
    /// The client-facing stage for the collection the import just started. Domain reports which collection it
    /// is writing; naming that as a job stage (alongside the parse/complete/fail states it knows nothing about)
    /// is the web layer's job.
    /// </summary>
    private static ReferenceDataImportStage StageOf(ReferenceDataImportCollection collection) => collection switch
    {
        ReferenceDataImportCollection.People => ReferenceDataImportStage.ImportingPeople,
        ReferenceDataImportCollection.TvShows => ReferenceDataImportStage.ImportingTvShows,
        ReferenceDataImportCollection.Movies => ReferenceDataImportStage.ImportingMovies,
        ReferenceDataImportCollection.Books => ReferenceDataImportStage.ImportingBooks,
        ReferenceDataImportCollection.VideoGames => ReferenceDataImportStage.ImportingVideoGames,
        ReferenceDataImportCollection.Albums => ReferenceDataImportStage.ImportingAlbums,
        _ => throw new ArgumentOutOfRangeException(nameof(collection), collection, null)
    };

    private static ReferenceDataImportCountsDto ToDto(ReferenceDataImportCounts counts) =>
        new() { Created = counts.Created, Updated = counts.Updated };

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
    /// Runs the periodic background sync (see <see cref="ReferenceSyncBackgroundService"/>) right now instead
    /// of waiting for its next tick - the same logic either way, only the staleness windows differ.
    /// Runs in the background; poll <see cref="GetSyncStatus"/> with the returned job id for progress, since a
    /// re-check across five domains can easily exceed a single request/response's own timeout.
    /// </summary>
    /// <param name="force">
    /// <c>true</c> re-checks every reference document and rebuilds every Explore ranking, however recently
    /// they were last enriched. The default runs exactly what the background tick would have taken (see
    /// <see cref="ReferenceSyncWindows.Periodic"/>), so a collection already synced within the window
    /// legitimately reports zero checked - it is the cheap option, and it spends no provider calls on
    /// documents that are already fresh.
    /// </param>
    [HttpPost("sync-now")]
    [ProducesResponseType(202)]
    public async Task<ActionResult<ReferenceSyncJobDto>> SyncNow([FromQuery] bool force = false)
    {
        var jobId = await syncJobStore.CreateAsync(this.GetUserId(), ReferenceSyncStage.SyncingTvShows);

        _ = RunSyncJobAsync(jobId, ReferenceSyncWindows.For(force));

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
    /// <para>
    /// It runs on <see cref="IHostApplicationLifetime.ApplicationStopping"/>, not an unbounded token. A pass
    /// takes minutes, so without that a shutdown leaves it working against a container being torn down: the
    /// singletons it depends on (the Mongo client, the HTTP clients, IGDB's rate limiter) are disposed out from
    /// under it, and every remaining step fails with <see cref="ObjectDisposedException"/> - including the
    /// final job-store write, which would leave the job reading "Running" forever. Confirmed in the running
    /// app: a shutdown mid-pass surfaced as a disposed <c>TokenBucketRateLimiter</c> deep inside an IGDB call.
    /// </para>
    /// </summary>
    private async Task RunSyncJobAsync(Guid jobId, ReferenceSyncWindows windows)
    {
        var cancellationToken = lifetime.ApplicationStopping;
        using var scope = scopeFactory.CreateScope();
        var scopedSyncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
        var scopedReconciliationService = scope.ServiceProvider.GetRequiredService<TvShowStatusReconciliationService>();
        var scopedExploreRefreshService = scope.ServiceProvider.GetRequiredService<ExploreCatalogueRefreshService>();
        var scopedJobStore = scope.ServiceProvider.GetRequiredService<JobStore<ReferenceSyncStage, ReferenceSyncResultDto>>();

        try
        {
            var result = await scopedSyncService.SyncStaleReferencesAsync(
                windows.References, stage => scopedJobStore.UpdateStageAsync(jobId, stage), cancellationToken);
            // an on-demand "sync now" reconciles finished-show status too, so its result matches the periodic pass's.
            result.FinishedShowsReopened = await scopedReconciliationService.ReconcileFinishedShowsAsync();
            // ...and covers the Explore discovery rankings on the same window, which is what makes this the
            // "run it now" control for those too - no separate admin endpoint needed.
            result.ApplyExploreRefresh(await scopedExploreRefreshService.RefreshAsync(windows.Explore, cancellationToken));
            await scopedJobStore.CompleteAsync(jobId, ReferenceSyncStage.Completed, result);
        }
        catch (OperationCanceledException)
        {
            // the API is going down, so this is neither a success nor a fault to investigate - just say so
            // plainly and stop. Best-effort: the job store may already be unusable at this point.
            try
            {
                await scopedJobStore.FailAsync(jobId, ReferenceSyncStage.Failed, "The API shut down before the sync finished. Start it again once the API is back up.");
            }
            catch (Exception writeFailure)
            {
                logger.LogWarning(writeFailure, "Could not record that sync job {JobId} was interrupted by shutdown.", jobId);
            }
        }
        catch (Exception ex)
        {
            await scopedJobStore.FailAsync(jobId, ReferenceSyncStage.Failed, ex.Message);
        }
    }

    /// <summary>
    /// Every registered provider an admin can search/link <paramref name="type"/> with, in priority order.
    /// Books and video games are the domains with more than one; TMDB/Discogs have exactly one each, so those
    /// types return an empty list and the caller shows no picker.
    /// </summary>
    [HttpGet("providers")]
    [ProducesResponseType(200)]
    public ActionResult<List<ReferenceProviderDto>> GetProviders([FromQuery] ReferenceItemType type)
    {
        IEnumerable<IReferenceProviderClient> clients = type switch
        {
            ReferenceItemType.Book => bookReferenceClientRegistry.All,
            ReferenceItemType.VideoGame => videoGameReferenceClientRegistry.All,
            _ => []
        };

        return Ok(clients.Select(c => new ReferenceProviderDto { Key = c.ProviderKey, DisplayName = c.DisplayName }).ToList());
    }

    /// <summary>
    /// Every domain whose primary rating source (the score shown as the pill / used for the "Ref ★" sort) is
    /// admin-selectable, with its available sources and the one currently selected. Only domains with more
    /// than one source appear - today video games (IGDB, IGDB's critic aggregate, Metacritic) and movies/TV
    /// (TMDB vs IMDb).
    /// </summary>
    [HttpGet("rating-sources")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<RatingSourceOptionDto>>> GetRatingSources()
    {
        var options = new List<RatingSourceOptionDto>();
        foreach (var domain in RatingSourceCatalog.SelectableDomains)
        {
            options.Add(new RatingSourceOptionDto
            {
                Domain = domain,
                AvailableSources = RatingSourceCatalog.AvailableSources(domain).ToList(),
                SelectedSource = await enrichmentService.GetPrimaryRatingSourceAsync(domain)
            });
        }

        return Ok(options);
    }

    /// <summary>
    /// Sets a domain's primary rating source. Only stores the choice - existing linked items keep their old
    /// denormalized rating until <see cref="RecomputeRatingSource"/> re-applies it, so a switch is visible
    /// and deliberate rather than silently reshuffling every list.
    /// </summary>
    [HttpPut("rating-sources/{domain}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> SetRatingSource(ReferenceItemType domain, [FromBody] SetRatingSourceRequestDto request)
    {
        // ArgumentException maps to a 400 via ApiExceptionFilterAttribute
        if (!RatingSourceCatalog.AvailableSources(domain).Contains(request.Source))
        {
            throw new ArgumentException($"'{request.Source}' is not a selectable rating source for {domain}.", nameof(request));
        }

        await appSettingRepository.SetReferenceRatingSourceAsync(domain.ToString(), request.Source);
        return NoContent();
    }

    /// <summary>The global Explore-feature settings (see <see cref="ExploreSettingsDto"/>).</summary>
    [HttpGet("explore-settings")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<ExploreSettingsDto>> GetExploreSettings() =>
        Ok(new ExploreSettingsDto { UseTmdbRanking = await appSettingRepository.GetExploreUseTmdbAsync() });

    /// <summary>Updates the global Explore-feature settings.</summary>
    [HttpPut("explore-settings")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> SetExploreSettings([FromBody] ExploreSettingsDto request)
    {
        await appSettingRepository.SetExploreUseTmdbAsync(request.UseTmdbRanking);
        return NoContent();
    }

    /// <summary>
    /// Re-applies a domain's current primary rating source to every already-linked tenant item - a single
    /// bulk pass over the (small, shared) reference collection, no provider calls. Run after switching the
    /// source via <see cref="SetRatingSource"/> so the list pills and sort reflect the new choice.
    /// </summary>
    [HttpPost("rating-sources/{domain}/recompute")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<RecomputeRatingsResultDto>> RecomputeRatingSource(ReferenceItemType domain)
    {
        var (referencesChecked, itemsUpdated) = await enrichmentService.RecomputeReferenceRatingsAsync(domain);
        return Ok(new RecomputeRatingsResultDto { ReferencesChecked = referencesChecked, ItemsUpdated = itemsUpdated });
    }

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
    /// <paramref name="provider"/> selects which registered provider to search with, for the domains that have
    /// more than one (see <see cref="GetProviders"/>); ignored for the rest. Null falls back to the
    /// deployment default.
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
                var games = await videoGameReferenceClientRegistry.Resolve(provider).SearchGamesAsync(title, year);
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
                await enrichmentService.ResolveVideoGameAsync(request.Title, request.Year, request.ExternalId, request.Provider);
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
