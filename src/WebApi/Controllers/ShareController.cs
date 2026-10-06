using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The owner side of sharing: issuing, listing and revoking share grants.
/// A grant lets one account, named by email, browse whole categories of the caller's collection read-only (see <see cref="SharedWithMeController"/> for the recipient side).
/// Member only, since sharing is outside the free preview tier.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/shares")]
public class ShareController(IShareRepository shareRepository, ShareDtoMapper mapper) : ControllerBase
{
    /// <summary>Every grant the caller issued, oldest first.</summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<ShareDto>>> Get()
    {
        var shares = await shareRepository.FindAllByOwnerIdAsync(this.GetUserId());
        return Ok(shares.ConvertAll(mapper.ToDto));
    }

    /// <summary>
    /// Issues a new grant.
    /// <c>OwnerId</c> and <c>OwnerDisplayName</c> come from the authenticated caller, never the body, and the recipient email is normalized lowercase, as the recipient is looked up.
    /// </summary>
    [HttpPost]
    [Consumes("application/json", "text/json")]
    [Produces("application/json")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<ShareDto>> Create([FromBody] CreateShareRequestDto request)
    {
        if (string.IsNullOrWhiteSpace(request.RecipientEmail))
        {
            return BadRequest(new { error = "A recipient email is required." });
        }

        if (request.IncludedCategories.Count == 0)
        {
            return BadRequest(new { error = "Select at least one category to share." });
        }

        var model = mapper.ToModel(request);
        model.OwnerId = this.GetUserId();
        model.OwnerDisplayName = this.GetDisplayName();
        model.RecipientEmail = request.RecipientEmail.Trim().ToLowerInvariant();
        // deduplicated, in case the client sent a category twice
        model.IncludedCategories = [.. model.IncludedCategories.Distinct()];

        var created = await shareRepository.CreateAsync(model);
        return Ok(mapper.ToDto(created));
    }

    /// <summary>
    /// Revokes one grant, the recipient's next read returning nothing.
    /// Owner-scoped in the query, so an id never revokes another owner's grant.
    /// </summary>
    [HttpDelete("{id}")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Delete(string id)
    {
        await shareRepository.DeleteAsync(id, this.GetUserId());
        return NoContent();
    }
}
