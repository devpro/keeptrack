using System;
using System.Collections.Generic;

namespace KeepTrack.Common.System;

/// <summary>
/// Represents a paginated result set, carrying the requested page of items alongside the total number of records matching the query.
/// </summary>
/// <typeparam name="T">The item type for this page.</typeparam>
public sealed record PagedResult<T>
{
    public List<T> Items { get; init; }

    public long TotalCount { get; init; }

    public int Page { get; init; }

    public int PageSize { get; init; }

    public int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);

    public bool HasPreviousPage => Page > 1;

    public bool HasNextPage => Page < TotalPages;

    public PagedResult(List<T> items, long totalCount, int page, int pageSize)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentOutOfRangeException.ThrowIfNegative(totalCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(page, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);

        Items = items;
        TotalCount = totalCount;
        Page = page;
        PageSize = pageSize;
    }

    /// <summary>
    /// Convenience factory, projects items without re-allocating the wrapper.
    /// </summary>
    public PagedResult<TOut> Map<TOut>(Func<T, TOut> selector) =>
        new(Items.ConvertAll(selector.Invoke), TotalCount, Page, PageSize);
}
