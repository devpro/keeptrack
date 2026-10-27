using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One page of items from a shared category, with the ones the recipient already has (<see cref="AlreadyInCollectionIds"/>), so the list marks them without a round trip per row.
/// </summary>
/// <typeparam name="TDto">The media item DTO for this category, such as <see cref="MovieDto"/>.</typeparam>
public class SharedCategoryPageDto<TDto>
{
    /// <summary>The items on this page (owned by the sharer, read-only for the recipient).</summary>
    public List<TDto> Items { get; set; } = [];

    /// <summary>Total items in the shared category matching the query, across all pages.</summary>
    public long TotalCount { get; set; }

    /// <summary>1-based page number.</summary>
    public int Page { get; set; }

    /// <summary>Items per page.</summary>
    public int PageSize { get; set; }

    /// <summary>The ids (on this page) the recipient already has an equivalent of in their own collection.</summary>
    public List<string> AlreadyInCollectionIds { get; set; } = [];
}

/// <summary>
/// The outcome of copying a shared item into the recipient's collection: the resulting item, new or already there, and whether it existed.
/// </summary>
/// <typeparam name="TDto">The media item DTO for this category.</typeparam>
public class CopyResultDto<TDto>
{
    /// <summary>The recipient's own item, newly created or the one they already had.</summary>
    public required TDto Item { get; set; }

    /// <summary>True when the recipient already owned an equivalent item, so nothing new was created.</summary>
    public bool AlreadyInCollection { get; set; }
}
