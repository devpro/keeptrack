using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Lets an admin/maintainer resolve titles the automatic TMDB match couldn't confidently handle
/// (ambiguous or zero results). Not per-tenant CRUD, so this doesn't extend <see cref="Controllers.DataCrudControllerBase{TDto,TModel}"/>.
/// </summary>
[ApiController]
[Authorize(Policy = "AdminOnly")]
[Route("api/reference-data")]
public class ReferenceDataAdminController(
    ITvShowRepository tvShowRepository,
    IMovieRepository movieRepository,
    ITmdbClient tmdbClient,
    ReferenceEnrichmentService enrichmentService,
    ReferenceSyncService syncService,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IPersonReferenceRepository personReferenceRepository) : ControllerBase
{
    private const string TvShowEntryName = "tvshow_reference.json";
    private const string MovieEntryName = "movie_reference.json";
    private const string PersonEntryName = "person_reference.json";

    /// <summary>
    /// Every reference document (TV shows, movies, cast) as a zip, so an admin can seed a fresh
    /// environment's reference data without re-earning every TMDB match one search at a time.
    /// </summary>
    [HttpGet("export")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Export()
    {
        var tvShows = await tvShowReferenceRepository.FindAllAsync();
        var movies = await movieReferenceRepository.FindAllAsync();
        var people = await personReferenceRepository.FindAllAsync();

        var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            await WriteJsonEntryAsync(archive, TvShowEntryName, tvShows);
            await WriteJsonEntryAsync(archive, MovieEntryName, movies);
            await WriteJsonEntryAsync(archive, PersonEntryName, people);
        }

        buffer.Position = 0;
        return File(buffer, "application/zip", "keeptrack-reference-data.zip");
    }

    /// <summary>
    /// Idempotent (upsert-by-id) re-import of a previously exported zip - re-running the same import
    /// twice is a no-op the second time, since every document already carries the id it was exported with.
    /// </summary>
    [HttpPost("import")]
    [RequestSizeLimit(50_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<ReferenceDataImportResultDto>> Import(IFormFile file)
    {
        if (file.Length == 0) return BadRequest();

        await using var uploadStream = file.OpenReadStream();
        using var archive = new ZipArchive(uploadStream, ZipArchiveMode.Read);

        var tvShowCount = 0;
        var movieCount = 0;
        var personCount = 0;

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

        return Ok(new ReferenceDataImportResultDto { TvShowCount = tvShowCount, MovieCount = movieCount, PersonCount = personCount });
    }

    private static async Task WriteJsonEntryAsync<T>(ZipArchive archive, string entryName, T value)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        await using var entryStream = entry.Open();
        await JsonSerializer.SerializeAsync(entryStream, value);
    }

    private static async Task<List<T>> ReadJsonEntryAsync<T>(ZipArchive archive, string entryName)
    {
        var entry = archive.GetEntry(entryName);
        if (entry is null) return [];

        await using var entryStream = entry.Open();
        return await JsonSerializer.DeserializeAsync<List<T>>(entryStream) ?? [];
    }

    /// <summary>
    /// Forces an immediate re-check of every reference document against TMDB, regardless of how recently
    /// it was last enriched - the same logic the periodic background sync runs on a schedule (see
    /// <see cref="ReferenceSyncBackgroundService"/>), just triggered on demand instead of waiting.
    /// </summary>
    [HttpPost("sync-now")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<ReferenceSyncResultDto>> SyncNow(CancellationToken cancellationToken) =>
        Ok(await syncService.SyncStaleReferencesAsync(TimeSpan.Zero, cancellationToken));

    /// <summary>
    /// Distinct (title, year) pairs, across every tenant, still missing a reference-data link.
    /// </summary>
    [HttpGet("unresolved")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<UnresolvedReferenceDto>>> GetUnresolved([FromQuery] ReferenceItemType type)
    {
        var pairs = type == ReferenceItemType.TvShow
            ? await tvShowRepository.FindDistinctUnresolvedTitleYearsAsync()
            : await movieRepository.FindDistinctUnresolvedTitleYearsAsync();

        return Ok(pairs.Select(p => new UnresolvedReferenceDto { Type = type, Title = p.Title, Year = p.Year }).ToList());
    }

    /// <summary>
    /// How many search candidates get enriched with a poster and top cast names - bounds the extra
    /// per-candidate credits calls to a small, admin-facing action, not the full ~20-result TMDB page.
    /// </summary>
    private const int MaxEnrichedCandidates = 5;

    private const int MaxCastNamesPerCandidate = 3;

    /// <summary>
    /// Live TMDB search, for an admin to pick the right candidate for an unresolved title. The top
    /// candidates are enriched with a poster and top-billed cast names to help tell apart near-identical
    /// results (remakes, regional variants, sequels sharing a title).
    /// </summary>
    [HttpGet("search")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<ReferenceSearchResultDto>>> Search([FromQuery] ReferenceItemType type, [FromQuery] string title, [FromQuery] int? year)
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
                TmdbId = result.TmdbId,
                Title = result.Title,
                Year = result.Year,
                Synopsis = result.Synopsis,
                PosterUrl = result.PosterUrl,
                TopCastNames = cast.OrderBy(c => c.Order).Take(MaxCastNamesPerCandidate).Select(c => c.Name).ToList()
            });
        }

        return Ok(dtos);
    }

    /// <summary>
    /// Links every tenant's (Title, Year) match to the chosen TMDB id and fetches its full details.
    /// </summary>
    [HttpPost("link")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Link([FromBody] LinkReferenceRequestDto request)
    {
        if (request.Type == ReferenceItemType.TvShow)
        {
            await enrichmentService.ResolveTvShowAsync(request.Title, request.Year, request.TmdbId);
        }
        else
        {
            await enrichmentService.ResolveMovieAsync(request.Title, request.Year, request.TmdbId);
        }

        return NoContent();
    }
}
