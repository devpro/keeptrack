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
/// Lets an admin resolve titles automatic matching left unlinked, across every reference-backed domain: TV shows, movies, books, video games and albums.
/// It is not per-tenant CRUD, so it doesn't extend <see cref="Controllers.DataCrudControllerBase{TDto,TModel}"/>.
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
    RatingSourceOptions ratingSourceOptions,
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
    /// Every reference document as a zip, so an admin can seed a fresh environment without earning every match again one search at a time.
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
    /// Imports a previously exported zip into whatever the target database already holds.
    /// Every document is matched by its <b>provider id</b> (TMDB, IGDB, Google Books, Discogs...), never by the <c>_id</c> it was exported with.
    /// <see cref="ReferenceDataImportService"/> explains why, and what a match merges rather than replaces.
    /// Re-running the same import updates the same documents in place.
    /// <para>
    /// It runs in the background, and <see cref="GetImportStatus"/> reports progress for the returned job id.
    /// A real export is tens of thousands of documents, each one a write.
    /// A blocking call would outlive the client's default 100s <c>HttpClient.Timeout</c>, reporting a failure for work that goes on to succeed.
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

        // buffered up front, since IFormFile's stream is invalid once this request finishes and the import runs after the response
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
    /// Runs the import on a background task with its own DI scope,
    /// since the request that started it has completed and its scoped services (the six repositories, its JobStore) are unusable.
    /// <para>
    /// It runs on <see cref="IHostApplicationLifetime.ApplicationStopping"/>, like <see cref="RunSyncJobAsync"/>.
    /// A shutdown mid-import would otherwise leave it writing against a disposed Mongo client, and the job reading "Running" forever.
    /// Stopping partway is safe, since re-running the same zip picks up what didn't land and updates what did.
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
                    // Also in the result, but logged so the collision leaves a server-side trail.
                    // The target holds two reference documents for one work, which the import won't merge on its own.
                    logger.LogWarning("Reference-data import skipped external id {ExternalId}: another document in this database already claims it.", skipped);
                }

                foreach (var duplicate in summary.PossibleDuplicates)
                {
                    // Logged for the same reason: two reference documents for one work, which only the admin reconciliation action merges.
                    logger.LogWarning("Reference-data import created a second document for {Work}: the target already had it under a different provider's id.", duplicate);
                }

                await scopedJobStore.CompleteAsync(jobId, ReferenceDataImportStage.Completed, new ReferenceDataImportResultDto
                {
                    TvShows = ToDto(summary.TvShows),
                    Movies = ToDto(summary.Movies),
                    People = ToDto(summary.People),
                    Books = ToDto(summary.Books),
                    VideoGames = ToDto(summary.VideoGames),
                    Albums = ToDto(summary.Albums),
                    SkippedExternalIds = summary.SkippedExternalIds,
                    PossibleDuplicates = summary.PossibleDuplicates
                });
            }
            catch (OperationCanceledException)
            {
                // The API is going down, which is neither a success nor a fault to investigate.
                // Best effort, since the job store may already be unusable.
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
    /// The client-facing stage for the collection the import just started.
    /// Domain reports which collection it is writing, and naming it as a job stage beside the parse, complete and fail states is the web layer's concern.
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
    /// Runs the periodic background sync (see <see cref="ReferenceSyncBackgroundService"/>) now instead of at its next tick,
    /// with the same logic and only the staleness windows differing.
    /// It runs in the background, and <see cref="GetSyncStatus"/> reports progress for the returned job id,
    /// since a re-check across five domains easily exceeds a request's timeout.
    /// </summary>
    /// <param name="force">
    /// <c>true</c> re-checks every reference document and rebuilds every Explore ranking, however recently enriched.
    /// The default runs exactly what the background tick would (see <see cref="ReferenceSyncWindows.Periodic"/>), so a collection synced within the window reports zero checked.
    /// It is the cheap option, spending no provider calls on fresh documents.
    /// </param>
    /// <param name="exploreOnly">
    /// <c>true</c> runs only the Explore ranking rebuild, skipping the five reference domains and the finished-show reconciliation.
    /// The two passes are separate calls inside one job, so this is a flag rather than a second endpoint.
    /// <para>
    /// The two halves cost very different amounts.
    /// The reference sync walks up to 500 documents per domain, each one or more provider calls, while a ranking rebuild is a handful of listing pages.
    /// Checking an Explore change then doesn't pay for a full reference pass, the most expensive action in the app with <paramref name="force"/>.
    /// </para>
    /// </param>
    [HttpPost("sync-now")]
    [ProducesResponseType(202)]
    public async Task<ActionResult<ReferenceSyncJobDto>> SyncNow([FromQuery] bool force = false, [FromQuery] bool exploreOnly = false)
    {
        var jobId = await syncJobStore.CreateAsync(
            this.GetUserId(), exploreOnly ? ReferenceSyncStage.RefreshingExplore : ReferenceSyncStage.SyncingTvShows);

        _ = RunSyncJobAsync(jobId, ReferenceSyncWindows.For(force), exploreOnly);

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
    /// Runs the sync on a background task with its own DI scope,
    /// since the request that started it has completed and its scoped services (<see cref="ReferenceSyncService"/>, its JobStore) are unusable.
    /// <para>
    /// It runs on <see cref="IHostApplicationLifetime.ApplicationStopping"/>, not an unbounded token.
    /// A pass takes minutes, and on shutdown the singletons it uses (the Mongo client, the HTTP clients, IGDB's rate limiter) are disposed under it.
    /// Every remaining step would then fail with <see cref="ObjectDisposedException"/>, the final job-store write included, leaving the job reading "Running" forever.
    /// </para>
    /// </summary>
    private async Task RunSyncJobAsync(Guid jobId, ReferenceSyncWindows windows, bool exploreOnly)
    {
        var cancellationToken = lifetime.ApplicationStopping;
        using var scope = scopeFactory.CreateScope();
        var scopedExploreRefreshService = scope.ServiceProvider.GetRequiredService<ExploreCatalogueRefreshService>();
        var scopedJobStore = scope.ServiceProvider.GetRequiredService<JobStore<ReferenceSyncStage, ReferenceSyncResultDto>>();

        try
        {
            // An Explore-only run leaves every reference count at zero, which is true of what it did.
            // The admin page hides them rather than reporting "0 checked" as if the pass had found nothing.
            var result = new ReferenceSyncResultDto();
            if (!exploreOnly)
            {
                var scopedSyncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
                var scopedReconciliationService = scope.ServiceProvider.GetRequiredService<TvShowStatusReconciliationService>();

                result = await scopedSyncService.SyncStaleReferencesAsync(
                    windows.References, stage => scopedJobStore.UpdateStageAsync(jobId, stage), cancellationToken);
                // an on-demand "sync now" reconciles finished-show status too, so its result matches the periodic pass's.
                result.FinishedShowsReopened = await scopedReconciliationService.ReconcileFinishedShowsAsync();
                await scopedJobStore.UpdateStageAsync(jobId, ReferenceSyncStage.RefreshingExplore);
            }

            // the Explore rankings run on the same windows, which makes this their "run it now" control too
            result.ApplyExploreRefresh(await scopedExploreRefreshService.RefreshAsync(windows.Explore, cancellationToken));
            await scopedJobStore.CompleteAsync(jobId, ReferenceSyncStage.Completed, result);
        }
        catch (OperationCanceledException)
        {
            // The API is going down, which is neither a success nor a fault to investigate.
            // Best effort, since the job store may already be unusable.
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
    /// Every registered provider an admin can search and link <paramref name="type"/> with, in priority order.
    /// Books and video games have more than one, while the TMDB and Discogs domains return an empty list and the caller shows no picker.
    /// </summary>
    [HttpGet("providers")]
    [ProducesResponseType(200)]
    public ActionResult<List<ReferenceProviderDto>> GetProviders([FromQuery] ReferenceItemType type)
    {
        (IEnumerable<IReferenceProviderClient> Clients, string DefaultProviderKey) providers = type switch
        {
            ReferenceItemType.Book => (bookReferenceClientRegistry.All, bookReferenceClientRegistry.DefaultProviderKey),
            ReferenceItemType.VideoGame => (videoGameReferenceClientRegistry.All, videoGameReferenceClientRegistry.DefaultProviderKey),
            _ => ([], string.Empty)
        };

        return Ok(providers.Clients
            .Select(c => new ReferenceProviderDto
            {
                Key = c.ProviderKey,
                DisplayName = c.DisplayName,
                IsDefault = string.Equals(c.ProviderKey, providers.DefaultProviderKey, StringComparison.OrdinalIgnoreCase)
            })
            .ToList());
    }

    /// <summary>
    /// Every domain whose primary rating source (the pill's score, and the "Ref ★" sort) is admin-selectable, with its available sources and the current selection.
    /// The video game entry follows the deployment's default provider: IGDB's two scores, or RAWG's own plus Metacritic on a deployment configured for RAWG.
    /// </summary>
    [HttpGet("rating-sources")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<RatingSourceOptionDto>>> GetRatingSources()
    {
        var options = new List<RatingSourceOptionDto>();
        foreach (var domain in ratingSourceOptions.SelectableDomains)
        {
            options.Add(new RatingSourceOptionDto
            {
                Domain = domain,
                AvailableSources = ratingSourceOptions.AvailableSources(domain).ToList(),
                SelectedSource = await enrichmentService.GetPrimaryRatingSourceAsync(domain)
            });
        }

        return Ok(options);
    }

    /// <summary>
    /// Sets a domain's primary rating source.
    /// It only stores the choice: linked items keep their denormalized rating until <see cref="RecomputeRatingSource"/> re-applies it.
    /// A switch is then deliberate rather than silently reshuffling every list.
    /// </summary>
    [HttpPut("rating-sources/{domain}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> SetRatingSource(ReferenceItemType domain, [FromBody] SetRatingSourceRequestDto request)
    {
        // ArgumentException maps to a 400 via ApiExceptionFilterAttribute
        if (!ratingSourceOptions.AvailableSources(domain).Contains(request.Source))
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
    /// Re-applies a domain's primary rating source to every linked tenant item, in bulk over the shared reference collection, with no provider call.
    /// It follows <see cref="SetRatingSource"/>, so list pills and sort reflect the new choice.
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
    /// Distinct (title, year) pairs, across every tenant, still missing a reference-data link.
    /// Books are handled apart, since their <see cref="IBookRepository.FindDistinctUnresolvedTitleYearsAsync"/> also returns an <c>Isbn</c> to prefill.
    /// The other four domains share a tuple shape that would never populate it.
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
    /// How many TV or movie search candidates get a poster and top cast names, which bounds the extra per-candidate credits calls.
    /// </summary>
    private const int MaxEnrichedCandidates = 5;

    private const int MaxCastNamesPerCandidate = 3;

    /// <summary>
    /// Live external-provider search, for an admin to pick the right candidate for an unresolved title.
    /// TV show and movie candidates also carry top-billed cast names, to tell apart near-identical results (remakes, regional variants, sequels sharing a title).
    /// <para>
    /// <paramref name="creator"/> is a book's author or an album's artist, passed to the provider's own author or artist field,
    /// since a common title alone returns many unrelated candidates.
    /// TV shows, movies and video games ignore it.
    /// </para>
    /// <para>
    /// <paramref name="provider"/> picks the provider for the domains with more than one (see <see cref="GetProviders"/>), null meaning the deployment default.
    /// </para>
    /// <para>
    /// <paramref name="isbn"/> is for books only:
    /// every book provider tries it first and widens to the title search when its catalogue lacks the edition (see <see cref="BookReferenceClientBase"/>).
    /// </para>
    /// </summary>
    [HttpGet("search")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<List<ReferenceSearchResultDto>>> Search([FromQuery] ReferenceItemType type, [FromQuery] string title, [FromQuery] int? year,
        [FromQuery] string? creator = null, [FromQuery] string? provider = null, [FromQuery] string? isbn = null)
    {
        // never call a provider with an empty title, a 400 through ApiExceptionFilterAttribute
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
    /// Provider reconciliation for video games: which reference documents lack an id from the current default provider, and which look like duplicates.
    /// <para>
    /// Video games only, since it is the one domain refreshed exclusively through the default provider (see <c>ReferenceEnrichmentService.RefreshVideoGameReferenceAsync</c>).
    /// A missing default-provider id is then a real gap.
    /// Books refresh through whichever provider linked them and have no such gap.
    /// </para>
    /// </summary>
    [HttpGet("provider-reconciliation")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<ProviderReconciliationDto>> GetProviderReconciliation()
    {
        var (provider, displayName, total, missing) = await enrichmentService.FindVideoGameProviderGapsAsync();
        var duplicates = await enrichmentService.FindDuplicateVideoGameReferencesAsync();

        return Ok(new ProviderReconciliationDto
        {
            Provider = provider,
            ProviderDisplayName = displayName,
            TotalReferences = total,
            Gaps = missing.Select(reference => new ProviderGapDto
            {
                ReferenceId = reference.Id!,
                Title = reference.Title,
                Year = reference.Year,
                Providers = reference.ExternalIds.Keys.OrderBy(key => key, StringComparer.Ordinal).ToList(),
                LastAttemptedAt = reference.ProviderAdoptionCheckedAt.TryGetValue(provider, out var attemptedAt) ? attemptedAt : null
            }).ToList(),
            Duplicates = duplicates.Select(group => new DuplicateReferenceGroupDto
            {
                Title = group[0].Title,
                References = group.Select(reference => new DuplicateReferenceDto
                {
                    ReferenceId = reference.Id!,
                    Title = reference.Title,
                    Year = reference.Year,
                    ExternalIds = reference.ExternalIds,
                    RatingSources = reference.Ratings.Keys.OrderBy(key => key, StringComparer.Ordinal).ToList(),
                    ImageUrl = reference.ImageUrl,
                    LastEnrichedAt = reference.LastEnrichedAt
                }).ToList()
            }).ToList()
        });
    }

    /// <summary>
    /// What the default video game provider offers for one stuck reference, with the candidates the automatic rule would have accepted flagged.
    /// Fetched per row rather than for the whole queue, since each row costs a provider call or two.
    /// </summary>
    /// <param name="query">
    /// Optional replacement for the reference's stored title, when the provider spells the work differently, or a pasted provider page URL for rows no query reaches.
    /// Candidates are still confirmed against the reference, so this widens what is found, never what counts as a match.
    /// </param>
    /// <param name="referenceId"></param>
    /// <param name="cancellationToken"></param>
    [HttpGet("provider-reconciliation/{referenceId}/candidates")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<List<ReferenceSearchResultDto>>> GetAdoptionCandidates(
        string referenceId, CancellationToken cancellationToken, [FromQuery] string? query = null)
    {
        var (candidates, matchingIds) = await enrichmentService.FindVideoGameAdoptionCandidatesAsync(referenceId, query, cancellationToken);
        return Ok(candidates.Select(candidate => new ReferenceSearchResultDto
        {
            ExternalId = candidate.ExternalId,
            Title = candidate.Title,
            Year = candidate.Year,
            ImageUrl = candidate.ImageUrl,
            // The synopsis slot says whether this is the automatic pick, the admin's question being "would this have linked itself?".
            // A listing carries no synopsis anyway.
            Synopsis = matchingIds.Contains(candidate.ExternalId) ? "Title and year match this reference." : null
        }).ToList());
    }

    /// <summary>
    /// Attaches an admin-chosen provider id to an existing video game reference and refreshes it through that provider.
    /// The id goes onto the existing document and never creates a second one, the state this screen exists to repair.
    /// </summary>
    [HttpPost("provider-reconciliation/{referenceId}/adopt")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> AdoptProviderId(string referenceId, [FromBody] AdoptProviderIdRequestDto request, CancellationToken cancellationToken)
    {
        await enrichmentService.AdoptVideoGameProviderIdAsync(referenceId, request.ExternalId, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Folds one duplicate video game reference into another.
    /// The survivor gains every provider id, rating and alias the other held, every tenant item linked to the absorbed one is re-pointed, and the absorbed document is deleted.
    /// </summary>
    [HttpPost("provider-reconciliation/merge")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<MergeReferencesResultDto>> MergeReferences([FromBody] MergeReferencesRequestDto request)
    {
        var (kept, itemsRepointed) = await enrichmentService.MergeVideoGameReferencesAsync(request.KeepReferenceId, request.MergeReferenceId);
        return Ok(new MergeReferencesResultDto { KeptReferenceId = kept.Id!, ItemsRepointed = itemsRepointed });
    }

    /// <summary>
    /// Links every tenant's (Title, Year) match to the chosen external provider id and fetches its full details.
    /// </summary>
    [HttpPost("link")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Link([FromBody] LinkReferenceRequestDto request)
    {
        var target = ReferenceLinkTarget.Matching(request.Title, request.Year, request.Creator);
        switch (request.Type)
        {
            case ReferenceItemType.TvShow:
                await enrichmentService.ResolveTvShowAsync(request.Title, request.Year, request.ExternalId, target);
                break;
            case ReferenceItemType.Movie:
                await enrichmentService.ResolveMovieAsync(request.Title, request.Year, request.ExternalId, target);
                break;
            case ReferenceItemType.Book:
                await enrichmentService.ResolveBookAsync(request.Title, request.Year, request.ExternalId, target, request.Provider, request.Isbn);
                break;
            case ReferenceItemType.VideoGame:
                await enrichmentService.ResolveVideoGameAsync(request.Title, request.Year, request.ExternalId, target, request.Provider);
                break;
            case ReferenceItemType.Album:
                // an album is its title and artist, so an admin names the artist whose albums the link reaches
                ArgumentException.ThrowIfNullOrWhiteSpace(request.Creator);
                await enrichmentService.ResolveAlbumAsync(request.Title, request.Year, request.ExternalId, target);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(request));
        }

        return NoContent();
    }
}
