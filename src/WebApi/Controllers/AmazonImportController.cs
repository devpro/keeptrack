using System.Diagnostics.CodeAnalysis;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Previews an Amazon.fr order-history export and commits the rows the user selected/edited in the review
/// UI as books (the only supported target for now - see <see cref="AmazonBookImportMergeService"/>).
/// Synchronous on both ends: unlike the TV Time import, there is no external API call in the loop, so even
/// a multi-year export completes well within a normal request.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import/amazon")]
public class AmazonImportController(IBookRepository bookRepository, AmazonOrderPreviewRowDtoMapper previewMapper) : ControllerBase
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
        var existingBooks = await FindAllBooksAsync(ownerId);
        var alreadyImportedOrderIds = AmazonBookImportMergeService.FindImportedOrderIds(existingBooks);

        await using var stream = file.OpenReadStream();
        var rows = AmazonOrderPreviewService.BuildPreview(stream, alreadyImportedOrderIds);

        return Ok(rows.Select(previewMapper.ToDto).ToList());
    }

    /// <summary>
    /// Creates/updates books from the rows the user selected in the review UI. A row whose (normalized)
    /// title matches an existing book - or a book created earlier in this same request - gets an
    /// additional owned version instead of a duplicate book; see
    /// <see cref="AmazonBookImportMergeService.ComputeCommitPlan"/>.
    /// </summary>
    [HttpPost("commit")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<AmazonImportCommitResultDto>> Commit(AmazonImportCommitRequestDto request)
    {
        var ownerId = this.GetUserId();
        var existingBooks = await FindAllBooksAsync(ownerId);

        var items = request.Items.Select(item => new AmazonBookImportRequestItem
        {
            Title = item.Title,
            AmazonTitle = item.AmazonTitle,
            Year = item.Year,
            Isbn = item.Isbn,
            OwnedVersion = new OwnedVersionModel
            {
                CopyType = Enum.Parse<Keeptrack.Domain.Models.CopyType>(item.CopyType.ToString()),
                Price = item.Price,
                Vendor = item.Vendor,
                AcquiredAt = item.AcquiredAt,
                Reference = item.Reference
            }
        }).ToList();

        var plan = AmazonBookImportMergeService.ComputeCommitPlan(ownerId, existingBooks, items);

        foreach (var book in plan.BooksToCreate)
        {
            await bookRepository.CreateAsync(book);
        }

        foreach (var book in plan.BooksToUpdate)
        {
            await bookRepository.UpdateAsync(book.Id!, book, ownerId);
        }

        return Ok(new AmazonImportCommitResultDto
        {
            BooksCreated = plan.BooksToCreate.Count,
            BooksMergedInto = plan.BooksToUpdate.Count,
            OwnedVersionsAdded = plan.OwnedVersionsAdded
        });
    }

    private async Task<List<BookModel>> FindAllBooksAsync(string ownerId) =>
        (await bookRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty })).Items;
}
