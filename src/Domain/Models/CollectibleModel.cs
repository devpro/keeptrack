using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class CollectibleModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public string? Brand { get; set; }

    public int? Year { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// The tenant's own optional cover image URL, shown on the list thumbnail and the detail page header.
    /// </summary>
    public string? ImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter only: matches when <see cref="OwnedVersions"/> is non-empty.
    /// Never persisted (see <see cref="MovieModel.IsOwned"/>).
    /// </summary>
    public bool IsOwned { get; set; }
}
