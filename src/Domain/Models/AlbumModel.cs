using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class AlbumModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Artist { get; set; }

    public int? Year { get; set; }

    public string? Genre { get; set; }

    public float? Rating { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// Tenant-owned cover image override - takes priority over the linked reference's own cover wherever
    /// a cover is shown (list thumbnail, detail page). Null means "use the reference's cover, if any" -
    /// the previous, only behavior.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only: matches if <see cref="OwnedVersions"/> is non-empty. Never persisted - see
    /// <see cref="MovieModel.IsOwned"/>.
    /// </summary>
    public bool IsOwned { get; set; }
}
