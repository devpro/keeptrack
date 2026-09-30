using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A read-only view of one personal (non-media) item a user shared with the caller: the parent item, its full
/// child history, and the computed metrics - everything the item's own detail page renders, in one response.
/// Personal categories (cars, houses, health) are view-only and never copyable, so unlike the media
/// <see cref="SharedCategoryPageDto{TDto}"/> there is no paging or "already in collection" annotation here.
/// </summary>
/// <typeparam name="TParent">The parent DTO (e.g. <see cref="CarDto"/>).</typeparam>
/// <typeparam name="TChild">The child history DTO (e.g. <see cref="CarHistoryDto"/>).</typeparam>
/// <typeparam name="TMetrics">The computed-metrics DTO (e.g. <see cref="CarMetricsDto"/>).</typeparam>
public class SharedDetailDto<TParent, TChild, TMetrics>
{
    /// <summary>The shared item itself (owned by the sharer, read-only for the caller).</summary>
    public required TParent Parent { get; set; }

    /// <summary>The item's full child history (refuels/maintenance, house events, health records).</summary>
    public List<TChild> Children { get; set; } = [];

    /// <summary>The computed metrics for this item (consumption/cost charts, reimbursement balance, ...).</summary>
    public required TMetrics Metrics { get; set; }

    /// <summary>The sharer's display name, for the recipient-side breadcrumb ("Shared with me > owner > item").</summary>
    public string? OwnerDisplayName { get; set; }
}
