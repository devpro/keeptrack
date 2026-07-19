using System.Diagnostics.CodeAnalysis;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Previews an Amazon.fr order-history export and commits the rows the user selected/edited in the review
/// UI as books, movies, TV shows, or video games (picked per row - see <see cref="AmazonImportMediaType"/>).
/// Synchronous on both ends: unlike the TV Time import, there is no external API call in the loop, so even
/// a multi-year export completes well within a normal request.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import/amazon")]
public class AmazonImportController(
    IBookRepository bookRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IVideoGameRepository videoGameRepository,
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

        var alreadyImportedOrderIds = new HashSet<string>();
        alreadyImportedOrderIds.UnionWith(AmazonImportMergeService.FindImportedOrderIds(existingBooks, b => b.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedOrderIds.UnionWith(AmazonImportMergeService.FindImportedOrderIds(existingMovies, m => m.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedOrderIds.UnionWith(AmazonImportMergeService.FindImportedOrderIds(existingTvShows, t => t.OwnedVersions.Select(v => v.Reference)));
        alreadyImportedOrderIds.UnionWith(AmazonImportMergeService.FindImportedOrderIds(existingVideoGames, g => g.Platforms.Select(p => p.Reference)));

        await using var stream = file.OpenReadStream();
        var rows = AmazonOrderPreviewService.BuildPreview(stream, alreadyImportedOrderIds);

        return Ok(rows.Select(previewMapper.ToDto).ToList());
    }

    /// <summary>
    /// Creates/updates items from the rows the user selected in the review UI, grouped by the media type
    /// each row was assigned. A row whose (normalized) title matches an existing item of the same type - or
    /// one created earlier in this same request - gets an additional owned copy instead of a duplicate
    /// item; see <see cref="AmazonImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>.
    /// </summary>
    [HttpPost("commit")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<AmazonImportCommitResultDto>> Commit(AmazonImportCommitRequestDto request)
    {
        var ownerId = this.GetUserId();
        var result = new AmazonImportCommitResultDto();

        foreach (var item in request.Items.Where(item => item.MediaType is null))
        {
            throw new ArgumentException($"A media type is required to import '{item.Title}'.");
        }

        var bookItems = request.Items.Where(i => i.MediaType == AmazonImportMediaType.Book).ToList();
        var movieItems = request.Items.Where(i => i.MediaType == AmazonImportMediaType.Movie).ToList();
        var tvShowItems = request.Items.Where(i => i.MediaType == AmazonImportMediaType.TvShow).ToList();
        var videoGameItems = request.Items.Where(i => i.MediaType == AmazonImportMediaType.VideoGame).ToList();

        foreach (var item in videoGameItems.Where(item => string.IsNullOrWhiteSpace(item.Platform)))
        {
            throw new ArgumentException($"A platform is required to import '{item.Title}' as a video game.");
        }

        if (bookItems.Count > 0)
        {
            var existingBooks = await FindAllAsync(bookRepository, ownerId, new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty });
            var (created, mergedInto, skipped) = await CommitAsync(
                bookRepository, existingBooks, bookItems.Select(ToOwnedItemRequestItem).ToList(),
                b => b.Title, b => b.OwnedVersions.Select(v => v.Reference),
                i => i.Title, i => i.OwnedVersion.Reference,
                item => new BookModel
                {
                    OwnerId = ownerId,
                    Title = item.Title,
                    Author = string.Empty,
                    Year = item.Year,
                    Isbn = item.Isbn,
                    Notes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, item.Isbn),
                    OwnedVersions = [item.OwnedVersion]
                },
                (book, item) => book.OwnedVersions.Add(item.OwnedVersion), ownerId);
            (result.BooksCreated, result.BooksMergedInto, result.BooksSkipped) = (created, mergedInto, skipped);
        }

        if (movieItems.Count > 0)
        {
            var existingMovies = await FindAllAsync(movieRepository, ownerId, new MovieModel { OwnerId = ownerId, Title = string.Empty });
            var (created, mergedInto, skipped) = await CommitAsync(
                movieRepository, existingMovies, movieItems.Select(ToOwnedItemRequestItem).ToList(),
                m => m.Title, m => m.OwnedVersions.Select(v => v.Reference),
                i => i.Title, i => i.OwnedVersion.Reference,
                item => new MovieModel
                {
                    OwnerId = ownerId,
                    Title = item.Title,
                    Year = item.Year,
                    Notes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, null),
                    OwnedVersions = [item.OwnedVersion]
                },
                (movie, item) => movie.OwnedVersions.Add(item.OwnedVersion), ownerId);
            (result.MoviesCreated, result.MoviesMergedInto, result.MoviesSkipped) = (created, mergedInto, skipped);
        }

        if (tvShowItems.Count > 0)
        {
            var existingTvShows = await FindAllAsync(tvShowRepository, ownerId, new TvShowModel { OwnerId = ownerId, Title = string.Empty });
            var (created, mergedInto, skipped) = await CommitAsync(
                tvShowRepository, existingTvShows, tvShowItems.Select(ToOwnedItemRequestItem).ToList(),
                t => t.Title, t => t.OwnedVersions.Select(v => v.Reference),
                i => i.Title, i => i.OwnedVersion.Reference,
                item => new TvShowModel
                {
                    OwnerId = ownerId,
                    Title = item.Title,
                    Year = item.Year,
                    Notes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, null),
                    OwnedVersions = [item.OwnedVersion]
                },
                (tvShow, item) => tvShow.OwnedVersions.Add(item.OwnedVersion), ownerId);
            (result.TvShowsCreated, result.TvShowsMergedInto, result.TvShowsSkipped) = (created, mergedInto, skipped);
        }

        if (videoGameItems.Count > 0)
        {
            var existingVideoGames = await FindAllAsync(videoGameRepository, ownerId, new VideoGameModel { OwnerId = ownerId, Title = string.Empty });
            var (created, mergedInto, skipped) = await CommitAsync(
                videoGameRepository, existingVideoGames, videoGameItems.Select(ToVideoGameRequestItem).ToList(),
                g => g.Title, g => g.Platforms.Select(p => p.Reference),
                i => i.Title, i => i.Platform.Reference,
                item => new VideoGameModel
                {
                    OwnerId = ownerId,
                    Title = item.Title,
                    Year = item.Year,
                    Notes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, null),
                    Platforms = [item.Platform]
                },
                (game, item) => game.Platforms.Add(item.Platform), ownerId);
            (result.VideoGamesCreated, result.VideoGamesMergedInto, result.VideoGamesSkipped) = (created, mergedInto, skipped);
        }

        return Ok(result);
    }

    private static AmazonOwnedItemImportRequestItem ToOwnedItemRequestItem(AmazonImportCommitItemDto item) => new()
    {
        Title = item.Title,
        AmazonTitle = item.AmazonTitle,
        Year = item.Year,
        Isbn = item.Isbn,
        OwnedVersion = ToOwnedVersion(item)
    };

    private static AmazonVideoGameImportRequestItem ToVideoGameRequestItem(AmazonImportCommitItemDto item) => new()
    {
        Title = item.Title,
        AmazonTitle = item.AmazonTitle,
        Year = item.Year,
        Platform = new VideoGamePlatformModel
        {
            Platform = item.Platform!,
            CopyType = ToDomainCopyType(item.CopyType),
            Price = item.Price,
            Vendor = item.Vendor,
            AcquiredAt = item.AcquiredAt,
            Reference = item.Reference
        }
    };

    private static OwnedVersionModel ToOwnedVersion(AmazonImportCommitItemDto item) => new()
    {
        CopyType = ToDomainCopyType(item.CopyType),
        Price = item.Price,
        Vendor = item.Vendor,
        AcquiredAt = item.AcquiredAt,
        Reference = item.Reference
    };

    private static Keeptrack.Domain.Models.CopyType ToDomainCopyType(Keeptrack.WebApi.Contracts.Dto.CopyType copyType) =>
        Enum.Parse<Keeptrack.Domain.Models.CopyType>(copyType.ToString());

    private static async Task<(int Created, int MergedInto, int Skipped)> CommitAsync<TModel, TRequestItem>(
        IDataRepository<TModel> repository,
        List<TModel> existingItems,
        List<TRequestItem> requestItems,
        Func<TModel, string> getExistingTitle,
        Func<TModel, IEnumerable<string?>> getExistingReferences,
        Func<TRequestItem, string> getItemTitle,
        Func<TRequestItem, string?> getItemReference,
        Func<TRequestItem, TModel> createNew,
        Action<TModel, TRequestItem> appendOwnedCopy,
        string ownerId)
        where TModel : class, IHasIdAndOwnerId
    {
        var plan = AmazonImportMergeService.ComputeCommitPlan(
            existingItems, requestItems, getExistingTitle, getExistingReferences, getItemTitle, getItemReference, createNew, appendOwnedCopy);

        foreach (var item in plan.ItemsToCreate)
        {
            await repository.CreateAsync(item);
        }

        foreach (var item in plan.ItemsToUpdate)
        {
            await repository.UpdateAsync(item.Id!, item, ownerId);
        }

        return (plan.ItemsToCreate.Count, plan.ItemsToUpdate.Count, plan.OwnedCopiesSkipped);
    }

    private static async Task<List<TModel>> FindAllAsync<TModel>(IDataRepository<TModel> repository, string ownerId, TModel blankSample)
        where TModel : IHasIdAndOwnerId =>
        (await repository.FindAllAsync(ownerId, 1, int.MaxValue, null, blankSample)).Items;
}
