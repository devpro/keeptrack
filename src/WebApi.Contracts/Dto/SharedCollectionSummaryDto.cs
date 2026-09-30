using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One collection shared *with* the caller, as it appears on their "shared with me" list: who shared it
/// and which categories they can browse read-only. The caller reads each category's items via
/// <c>GET /api/shared-with-me/{shareId}/{category}</c>.
/// </summary>
public class SharedCollectionSummaryDto
{
    /// <summary>The share grant's id - the handle for reading its categories and copying media items.</summary>
    public required string ShareId { get; set; }

    /// <summary>The sharer's display name (or email), for showing who shared this collection.</summary>
    public string? OwnerDisplayName { get; set; }

    /// <summary>The categories the sharer exposed to the caller.</summary>
    public List<ShareCategory> IncludedCategories { get; set; } = [];
}
