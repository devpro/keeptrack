using System;
using System.Collections.Generic;

namespace Keeptrack.Common.System;

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

    public PagedResult<TOut> Map<TOut>(Func<T, TOut> selector) =>
        new(Items.ConvertAll(selector.Invoke), TotalCount, Page, PageSize);
}
