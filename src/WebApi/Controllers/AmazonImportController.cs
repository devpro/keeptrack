using System.Diagnostics.CodeAnalysis;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
// Both Domain.Models (imported above) and Contracts.Dto (a global using) declare ImportMediaType/CopyType.
// The DTOs the request carries use the Contracts ones; these aliases keep the mapping below unambiguous.
using AmazonMediaType = Keeptrack.WebApi.Contracts.Dto.AmazonImportMediaType;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Previews an Amazon.fr order-history export and commits the rows the user selected/edited in the review
/// UI as books, movies, TV shows, video games, gear, or collectibles (picked per row - see <see cref="AmazonImportMediaType"/>).
/// Synchronous on both ends: unlike the TV Time import, there is no external API call in the loop, so even
/// a multi-year export completes well within a normal request.
/// The create/merge/dedup work is delegated to the shared <see cref="OwnedItemImportCommitCoordinator"/> (the
/// same engine the generic store/CSV importer uses); this controller only parses Amazon's specific export and
/// builds the reference/provenance text that is genuinely Amazon-specific.
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
    /// Parses the uploaded order-history CSV and returns every line item for review - nothing is persisted
    /// by this call. Amazon's export carries no category column, so every row is returned; the review UI
    /// defaults to showing only <see cref="AmazonOrderPreviewRowDto.LooksLikeBook"/> rows.
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

        // "Already imported" must be checked across every type, not just books - a row previously imported
        // as a movie must still be flagged when the same export is uploaded again.
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
    /// Creates/updates items from the rows the user selected in the review UI, grouped by the media type
    /// each row was assigned. A row whose (normalized) title matches an existing item of the same type - or
    /// one created earlier in this same request - gets an additional owned copy instead of a duplicate
    /// item; see <see cref="OwnedItemImportCommitCoordinator.CommitAsync"/>.
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
            // The original, unedited Amazon listing text - kept in the created item's notes since reference-data
            // linking is expected to overwrite Title (and, for a book, ISBN) with canonical values later.
            ProvenanceNotes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, isBook ? item.Isbn : null),
            Year = item.Year,
            // Amazon's export has no author column; books are created author-less (the coordinator stores "").
            Author = null,
            Isbn = isBook ? item.Isbn : null,
            Platform = isVideoGame ? item.Platform : null,
            OwnedVersion = new OwnedVersionModel
            {
                CopyType = ToDomainCopyType(item.CopyType),
                Price = item.Price,
                Vendor = item.Vendor,
                AcquiredAt = item.AcquiredAt,
                // Derived server-side from the order id + ASIN the preview row reported, never from a
                // client-supplied Reference string - this is what disambiguates two different items sharing one
                // Amazon order and what a later re-preview dedups against.
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
