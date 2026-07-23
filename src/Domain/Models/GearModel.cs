using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class GearModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public string? Brand { get; set; }

    /// <summary>
    /// Free-text category (e.g. "Electronics", "Camping") - suggested from the tenant's other gear but
    /// not a closed list. Unlike a blog's tags, one gear item has exactly one category.
    /// </summary>
    public string? Category { get; set; }

    public int? Year { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only: matches if <see cref="OwnedVersions"/> is non-empty. Never persisted - see
    /// <see cref="MovieModel.IsOwned"/>.
    /// </summary>
    public bool IsOwned { get; set; }
}
