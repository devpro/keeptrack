using System.Diagnostics.CodeAnalysis;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
// Domain.Models and Contracts.Dto both declare ImportMediaType and CopyType, so aliases keep the mapping unambiguous
using AmazonMediaType = Keeptrack.WebApi.Contracts.Dto.AmazonImportMediaType;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Previews an Amazon.fr order-history export, then commits the rows selected in the review UI, each as the type picked for it (<see cref="AmazonImportMediaType"/>).
/// Synchronous, since no external call runs in the loop, so even a multi-year export completes within a request.
/// <see cref="OwnedItemImportCommitCoordinator"/> creates and merges, and this controller only parses the export and builds the Amazon-specific reference and provenance text.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import/amazon")]
public class AmazonImportController(
    IBookRepository bookRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IVideoGameRepository videoGameRepository,
    IGearRepository gearRepository,
    ICollectibleRepository collectibleRepository,
    AmazonOrderPreviewRowDtoMapper previewMapper) : ControllerBase
{
    /// <summary>
    /// Parses the uploaded order-history CSV and returns every line item for review, persisting nothing.
    /// The export has no category column, so every row is returned, and the review UI first shows only <see cref="AmazonOrderPreviewRowDto.LooksLikeBook"/> rows.
    /// </summary>
    [HttpPost("preview")]
    [RequestSizeLimit(20_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (20 MB), deliberately above Sonar's 8 MB default: a multi-year Amazon order-history " +
                        "export can be sizeable, and the endpoint is authenticated, member-only, admin-of-your-own-data.")]
    public async Task<ActionResult<List<AmazonOrderPreviewRowDto>>> Preview(IFormFile file)
    {
        if (file.Length == 0)
        {
            return BadRequest();
        }

        var ownerId = this.GetUserId();

        // checked across every type, so a row imported earlier as a movie is still flagged
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
        var rows = AmazonOrderPreviewService.BuildPreview(stream, alreadyImportedReferences);

        return Ok(rows.Select(previewMapper.ToDto).ToList());
    }

    /// <summary>
    /// Creates or updates items from the selected rows, grouped by the type each row was given.
    /// A row whose normalized title matches an item of its type, existing or created earlier in the request, adds a copy rather than a duplicate (see <see cref="OwnedItemImportCommitCoordinator.CommitAsync"/>).
    /// </summary>
    [HttpPost("commit")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<AmazonImportCommitResultDto>> Commit(AmazonImportCommitRequestDto request)
    {
        var ownerId = this.GetUserId();

        var itemMissingMediaType = request.Items.FirstOrDefault(item => item.MediaType is null);
        if (itemMissingMediaType is not null)
        {
            throw new ArgumentException($"A media type is required to import '{itemMissingMediaType.Title}'.");
        }

        var videoGameItemMissingPlatform = request.Items.FirstOrDefault(item =>
            item.MediaType == AmazonMediaType.VideoGame && string.IsNullOrWhiteSpace(item.Platform));
        if (videoGameItemMissingPlatform is not null)
        {
            throw new ArgumentException($"A platform is required to import '{videoGameItemMissingPlatform.Title}' as a video game.");
        }

        var inputs = request.Items.Select(ToInput).ToList();

        var counts = await OwnedItemImportCommitCoordinator.CommitAsync(
            ownerId, inputs,
            bookRepository, movieRepository, tvShowRepository, videoGameRepository, gearRepository, collectibleRepository);

        return Ok(new AmazonImportCommitResultDto
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
            CollectiblesSkipped = counts.Collectibles.Skipped
        });
    }

    private static OwnedItemImportInput ToInput(AmazonImportCommitItemDto item)
    {
        var isBook = item.MediaType == AmazonMediaType.Book;
        var isVideoGame = item.MediaType == AmazonMediaType.VideoGame;

        return new OwnedItemImportInput
        {
            MediaType = Enum.Parse<Keeptrack.Domain.Models.ImportMediaType>(item.MediaType!.Value.ToString()),
            Title = item.Title,
            // Amazon's original listing text, kept in the notes since reference linking may overwrite the title and a book's ISBN
            ProvenanceNotes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, isBook ? item.Isbn : null),
            Year = item.Year,
            // the export has no author column, so books are created without one
            Author = null,
            Isbn = isBook ? item.Isbn : null,
            Platform = isVideoGame ? item.Platform : null,
            OwnedVersion = new OwnedVersionModel
            {
                CopyType = ToDomainCopyType(item.CopyType),
                Price = item.Price,
                Vendor = item.Vendor,
                AcquiredAt = item.AcquiredAt,
                // built from the order id and ASIN, never from client text, which tells apart two items of one order and is what a later preview checks
                Reference = AmazonImportMergeService.FormatOrderReference(item.OrderId, item.Asin)
            }
        };
    }

    private static Keeptrack.Domain.Models.CopyType ToDomainCopyType(Keeptrack.WebApi.Contracts.Dto.CopyType copyType) =>
        Enum.Parse<Keeptrack.Domain.Models.CopyType>(copyType.ToString());

    private static async Task<List<TModel>> FindAllAsync<TModel>(IDataRepository<TModel> repository, string ownerId, TModel blankSample)
        where TModel : IHasIdAndOwnerId =>
        (await repository.FindAllAsync(ownerId, 1, int.MaxValue, null, blankSample)).Items;
}
