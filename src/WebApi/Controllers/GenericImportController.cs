using System.Diagnostics.CodeAnalysis;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
// Both Domain.Models (imported above) and Contracts.Dto (a global using) declare ImportMediaType/CopyType.
// The DTOs the request carries use the Contracts ones; this alias keeps the comparisons below unambiguous.
using ContractsImportMediaType = Keeptrack.WebApi.Contracts.Dto.ImportMediaType;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Previews a generic store/CSV import (any retailer export the user has reshaped into the canonical column set
/// in a spreadsheet) and commits the rows the user selected/edited in the review UI. The store-agnostic
/// generalization of <see cref="AmazonImportController"/>: vendor and each row's media type are read from
/// columns rather than hardcoded/guessed, so a well-prepared "Type" column pre-selects every row's type. Both
/// controllers share the same create/merge orchestration - <see cref="OwnedItemImportCommitCoordinator"/> -
/// and the same dedup engine, differing only in parsing and reference/provenance text.
/// Synchronous on both ends: there is no external API call in the loop, so even a multi-year export completes
/// well within a normal request.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import/generic")]
public class GenericImportController(
    IBookRepository bookRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IVideoGameRepository videoGameRepository,
    IGearRepository gearRepository,
    ICollectibleRepository collectibleRepository,
    GenericImportPreviewRowDtoMapper previewMapper) : ControllerBase
{
    /// <summary>
    /// Parses the uploaded CSV and returns every line item for review - nothing is persisted by this call. A
    /// row is flagged <see cref="GenericImportPreviewRowDto.AlreadyImported"/> when its order reference already
    /// exists on an owned copy of any type.
    /// </summary>
    [HttpPost("preview")]
    [RequestSizeLimit(20_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (20 MB), deliberately above Sonar's 8 MB default: a multi-year " +
                        "order-history export can be sizeable, and the endpoint is authenticated, member-only, admin-of-your-own-data.")]
    public async Task<ActionResult<List<GenericImportPreviewRowDto>>> Preview(IFormFile file)
    {
        if (file.Length == 0)
        {
            return BadRequest();
        }

        var ownerId = this.GetUserId();

        // "Already imported" is checked across every type, not just one - a row previously imported as a movie
        // must still be flagged when the same file is uploaded again.
        var existingBooks = await FindAllAsync(bookRepository, ownerId, new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty });
        var existingMovies = await FindAllAsync(movieRepository, ownerId, new MovieModel { OwnerId = ownerId, Title = string.Empty });
        var existingTvShows = await FindAllAsync(tvShowRepository, ownerId, new TvShowModel { OwnerId = ownerId, Title = string.Empty });
        var existingVideoGames = await FindAllAsync(videoGameRepository, ownerId, new VideoGameModel { OwnerId = ownerId, Title = string.Empty });
        var existingGear = await FindAllAsync(gearRepository, ownerId, new GearModel { OwnerId = ownerId, Title = string.Empty });
        var existingCollectibles = await FindAllAsync(collectibleRepository, ownerId, new CollectibleModel { OwnerId = ownerId, Title = string.Empty });

        var alreadyImportedReferences = new HashSet<string>();
        alreadyImportedReferences.UnionWith(OwnedItemImportMergeService.FindImportedReferences(existingBooks, b => b.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedReferences.UnionWith(OwnedItemImportMergeService.FindImportedReferences(existingMovies, m => m.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedReferences.UnionWith(OwnedItemImportMergeService.FindImportedReferences(existingTvShows, t => t.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedReferences.UnionWith(OwnedItemImportMergeService.FindImportedReferences(existingVideoGames, g => g.Platforms.Select(p => p.Reference)));
        alreadyImportedReferences.UnionWith(OwnedItemImportMergeService.FindImportedReferences(existingGear, g => g.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedReferences.UnionWith(OwnedItemImportMergeService.FindImportedReferences(existingCollectibles, c => c.OwnedVersions.Select(v => v.Reference)));

        await using var stream = file.OpenReadStream();
        var rows = GenericImportService.BuildPreview(stream, alreadyImportedReferences);

        return Ok(rows.Select(previewMapper.ToDto).ToList());
    }

    /// <summary>
    /// Creates/updates items from the rows the user selected, grouped by the media type each row was assigned.
    /// A row whose (normalized) title matches an existing item of the same type - or one created earlier in
    /// this same request - gets an additional owned copy instead of a duplicate; see
    /// <see cref="OwnedItemImportCommitCoordinator.CommitAsync"/>.
    /// </summary>
    [HttpPost("commit")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<GenericImportCommitResultDto>> Commit(GenericImportCommitRequestDto request)
    {
        var ownerId = this.GetUserId();

        var itemMissingMediaType = request.Items.FirstOrDefault(item => item.MediaType is null);
        if (itemMissingMediaType is not null)
        {
            throw new ArgumentException($"A type is required to import '{itemMissingMediaType.Title}'.");
        }

        var videoGameItemMissingPlatform = request.Items.FirstOrDefault(item =>
            item.MediaType == ContractsImportMediaType.VideoGame && string.IsNullOrWhiteSpace(item.Platform));
        if (videoGameItemMissingPlatform is not null)
        {
            throw new ArgumentException($"A platform is required to import '{videoGameItemMissingPlatform.Title}' as a video game.");
        }

        var inputs = request.Items.Select(ToInput).ToList();

        var counts = await OwnedItemImportCommitCoordinator.CommitAsync(
            ownerId, inputs,
            bookRepository, movieRepository, tvShowRepository, videoGameRepository, gearRepository, collectibleRepository);

        return Ok(new GenericImportCommitResultDto
        {
            BooksCreated = counts.Books.Created,
            BooksMergedInto = counts.Books.MergedInto,
            BooksSkipped = counts.Books.Skipped,
            MoviesCreated = counts.Movies.Created,
            MoviesMergedInto = counts.Movies.MergedInto,
            MoviesSkipped = counts.Movies.Skipped,
            TvShowsCreated = counts.TvShows.Created,
            TvShowsMergedInto = counts.TvShows.MergedInto,
            TvShowsSkipped = counts.TvShows.Skipped,
            VideoGamesCreated = counts.VideoGames.Created,
            VideoGamesMergedInto = counts.VideoGames.MergedInto,
            VideoGamesSkipped = counts.VideoGames.Skipped,
            GearCreated = counts.Gear.Created,
            GearMergedInto = counts.Gear.MergedInto,
            GearSkipped = counts.Gear.Skipped,
            CollectiblesCreated = counts.Collectibles.Created,
            CollectiblesMergedInto = counts.Collectibles.MergedInto,
            CollectiblesSkipped = counts.Collectibles.Skipped,
            RowsImported = counts.RowsImported,
            SkippedRowTitles = counts.SkippedTitles
        });
    }

    private static OwnedItemImportInput ToInput(GenericImportCommitItemDto item)
    {
        var isBook = item.MediaType == ContractsImportMediaType.Book;
        var isVideoGame = item.MediaType == ContractsImportMediaType.VideoGame;

        return new OwnedItemImportInput
        {
            MediaType = Enum.Parse<Keeptrack.Domain.Models.ImportMediaType>(item.MediaType!.Value.ToString()),
            Title = item.Title,
            // Provenance notes preserve the source's original listing text, since reference-data linking is
            // expected to overwrite Title later. The ISBN line is only meaningful for a book.
            ProvenanceNotes = GenericImportService.BuildProvenanceNotes(item.Vendor, item.SourceTitle, isBook ? item.Isbn : null),
            Year = item.Year,
            Author = isBook ? item.Author : null,
            Isbn = isBook ? item.Isbn : null,
            Platform = isVideoGame ? item.Platform : null,
            OwnedVersion = new OwnedVersionModel
            {
                CopyType = Enum.Parse<Keeptrack.Domain.Models.CopyType>(item.CopyType.ToString()),
                Price = item.Price,
                Vendor = item.Vendor,
                AcquiredAt = item.AcquiredAt,
                // The reference carries the Website label + order id + product id (with SourceTitle as the
                // product-id fallback so it matches what preview checked against) - derived server-side, never
                // from a client-supplied Reference string. Independent of the Vendor field above; the order
                // id + product id are what disambiguate two different items sharing one order on re-import.
                Reference = GenericImportService.FormatReference(item.Website, item.OrderId, item.ProductId, item.SourceTitle),
                // Condition is preserved on the copy's Product field rather than dropped (the one behavioral
                // difference from the Amazon importer).
                ProductName = string.IsNullOrWhiteSpace(item.Condition) ? null : item.Condition.Trim()
            }
        };
    }

    private static async Task<List<TModel>> FindAllAsync<TModel>(IDataRepository<TModel> repository, string ownerId, TModel blankSample)
        where TModel : IHasIdAndOwnerId =>
        (await repository.FindAllAsync(ownerId, 1, int.MaxValue, null, blankSample)).Items;
}
