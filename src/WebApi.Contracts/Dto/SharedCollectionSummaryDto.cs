using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One collection shared with the caller, as on their "shared with me" list: who shared it and which categories they can browse read-only.
/// The caller reads each category's items via <c>GET /api/shared-with-me/{shareId}/{category}</c>.
/// </summary>
public class SharedCollectionSummaryDto
{
    /// <summary>The grant's id, used to read its categories and copy media items.</summary>
    public required string ShareId { get; set; }

    /// <summary>The sharer's display name or email.</summary>
    public string? OwnerDisplayName { get; set; }

    /// <summary>The categories the sharer exposed to the caller.</summary>
    public List<ShareCategory> IncludedCategories { get; set; } = [];
}
