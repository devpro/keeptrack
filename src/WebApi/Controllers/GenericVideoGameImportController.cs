using System.Diagnostics.CodeAnalysis;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Previews a generic video game transaction-history export and commits the rows the user selected/edited in
/// the review UI as video games. Unlike <see cref="AmazonImportController"/>, every row is always a video
/// game (the export is store purchase history for games specifically), so there's no per-row media-type
/// picker and no generic multi-type commit branching - just one direct call into the shared
/// <see cref="OwnedItemImportMergeService"/> engine.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import/video-games")]
public class GenericVideoGameImportController(
    IVideoGameRepository videoGameRepository,
    GenericVideoGameImportPreviewRowDtoMapper previewMapper) : ControllerBase
{
    /// <summary>
    /// Parses the uploaded transaction-history CSV and returns every line item for review - nothing is
    /// persisted by this call.
    /// </summary>
    [HttpPost("preview")]
    [RequestSizeLimit(20_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (20 MB), deliberately above Sonar's 8 MB default: a multi-year " +
                        "transaction-history export can be sizeable, and the endpoint is authenticated, member-only, admin-of-your-own-data.")]
    public async Task<ActionResult<List<GenericVideoGameImportPreviewRowDto>>> Preview(IFormFile file)
    {
        if (file.Length == 0)
        {
            return BadRequest();
        }

        var ownerId = this.GetUserId();

        var existingVideoGames = await FindAllAsync(ownerId);
        var alreadyImportedReferences = OwnedItemImportMergeService.FindImportedReferences(existingVideoGames, g => g.Platforms.Select(p => p.Reference));

        await using var stream = file.OpenReadStream();
        var rows = GenericVideoGameImportService.BuildPreview(stream, alreadyImportedReferences);

        return Ok(rows.Select(previewMapper.ToDto).ToList());
    }

    /// <summary>
    /// Creates/updates video games from the rows the user selected in the review UI. A row whose (normalized)
    /// title matches an existing video game - or one created earlier in this same request - gets an
    /// additional platform entry instead of a duplicate item; see
    /// <see cref="OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>.
    /// </summary>
    [HttpPost("commit")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<GenericVideoGameImportCommitResultDto>> Commit(GenericVideoGameImportCommitRequestDto request)
    {
        var ownerId = this.GetUserId();

        var itemMissingPlatform = request.Items.FirstOrDefault(item => string.IsNullOrWhiteSpace(item.Platform));
        if (itemMissingPlatform is not null)
        {
            throw new ArgumentException($"A platform is required to import '{itemMissingPlatform.Title}'.");
        }

        var existingVideoGames = await FindAllAsync(ownerId);
        var requestItems = request.Items.Select(ToRequestItem).ToList();

        var plan = OwnedItemImportMergeService.ComputeCommitPlan(
            existingVideoGames, requestItems,
            g => g.Title, g => g.Platforms.Select(p => p.Reference),
            i => i.Title, i => i.Platform.Reference,
            item => new VideoGameModel
            {
                OwnerId = ownerId,
                Title = item.Title,
                Year = item.Year,
                Notes = GenericVideoGameImportService.BuildProvenanceNotes(item.Platform.Vendor!, item.SourceTitle),
                Platforms = [item.Platform]
            },
            (game, item) => game.Platforms.Add(item.Platform));

        foreach (var item in plan.ItemsToCreate)
        {
            await videoGameRepository.CreateAsync(item);
        }

        foreach (var item in plan.ItemsToUpdate)
        {
            await videoGameRepository.UpdateAsync(item.Id!, item, ownerId);
        }

        return Ok(new GenericVideoGameImportCommitResultDto
        {
            VideoGamesCreated = plan.ItemsToCreate.Count,
            VideoGamesMergedInto = plan.ItemsToUpdate.Count,
            VideoGamesSkipped = plan.OwnedCopiesSkipped,
            RowsImported = plan.OwnedCopiesAdded,
            SkippedRowTitles = plan.SkippedTitles
        });
    }

    private static GenericVideoGameImportRequestItem ToRequestItem(GenericVideoGameImportCommitItemDto item) => new()
    {
        Title = item.Title,
        SourceTitle = item.SourceTitle,
        Year = item.Year,
        Platform = new VideoGamePlatformModel
        {
            Platform = item.Platform!,
            CopyType = ToDomainCopyType(item.CopyType),
            ProductName = item.ProductName,
            Price = item.Price,
            Vendor = item.Vendor,
            AcquiredAt = item.AcquiredAt,
            // Derived server-side from the transaction id + order id + product name the preview row
            // reported, never from a client-supplied Reference string - the product name is what
            // disambiguates two different items sharing one transaction/order (a single transaction can
            // bundle several products), and the whole string doubles as the exact-match dedup key on a re-import.
            Reference = GenericVideoGameImportService.FormatReference(item.TransactionId, item.OrderId, item.ProductName, item.SourceTitle)
        }
    };

    private static Keeptrack.Domain.Models.CopyType ToDomainCopyType(Keeptrack.WebApi.Contracts.Dto.CopyType copyType) =>
        Enum.Parse<Keeptrack.Domain.Models.CopyType>(copyType.ToString());

    private async Task<List<VideoGameModel>> FindAllAsync(string ownerId) =>
        (await videoGameRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, new VideoGameModel { OwnerId = ownerId, Title = string.Empty })).Items;
}
