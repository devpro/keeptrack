using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One page of items from a shared category, plus which of them the recipient already has in their own
/// collection (<see cref="AlreadyInCollectionIds"/> holds the sharer-side item ids that matched something
/// the recipient owns) - so the list can show "already in your collection" without a per-row round trip.
/// </summary>
/// <typeparam name="TDto">The media item DTO for this category (e.g. <see cref="MovieDto"/>).</typeparam>
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
/// The outcome of copying a shared item into the recipient's own collection: the resulting item (the newly
/// created one, or the pre-existing one when it was already there) and whether it already existed.
/// </summary>
/// <typeparam name="TDto">The media item DTO for this category.</typeparam>
public class CopyResultDto<TDto>
{
    /// <summary>The recipient's own item - freshly created, or the one they already had.</summary>
    public required TDto Item { get; set; }

    /// <summary>True when the recipient already owned an equivalent item, so nothing new was created.</summary>
    public bool AlreadyInCollection { get; set; }
}
