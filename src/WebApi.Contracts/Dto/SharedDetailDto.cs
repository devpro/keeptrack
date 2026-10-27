using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A read-only view of one personal item shared with the caller: the item, its whole history and its metrics, everything its detail page renders, in one response.
/// Personal categories (cars, houses, health) are never copyable, so unlike <see cref="SharedCategoryPageDto{TDto}"/> there is no paging nor "already in collection" marking.
/// </summary>
/// <typeparam name="TParent">The parent DTO, such as <see cref="CarDto"/>.</typeparam>
/// <typeparam name="TChild">The child history DTO, such as <see cref="CarHistoryDto"/>.</typeparam>
/// <typeparam name="TMetrics">The computed-metrics DTO, such as <see cref="CarMetricsDto"/>.</typeparam>
public class SharedDetailDto<TParent, TChild, TMetrics>
{
    /// <summary>The shared item itself (owned by the sharer, read-only for the caller).</summary>
    public required TParent Parent { get; set; }

    /// <summary>The item's whole history: refuels and maintenance, house events, health records.</summary>
    public List<TChild> Children { get; set; } = [];

    /// <summary>The computed metrics for this item: consumption and cost charts, reimbursement balance.</summary>
    public required TMetrics Metrics { get; set; }

    /// <summary>The sharer's display name, for the recipient-side breadcrumb ("Shared with me > owner > item").</summary>
    public string? OwnerDisplayName { get; set; }
}
