using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class VideoGameModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public List<VideoGamePlatformModel> Platforms { get; set; } = [];

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// Tenant-owned cover image override - takes priority over the linked reference's own cover wherever
    /// a cover is shown (list thumbnail, detail page). Null means "use the reference's cover, if any" -
    /// the previous, only behavior.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    /// <summary>
    /// Filter-only: matches if <see cref="Platforms"/> is non-empty. Never persisted - a platform entry
    /// (with its own <see cref="CopyType"/>) is this type's owned copy, so ownership derives from having
    /// at least one, the same rule as <see cref="MovieModel.IsOwned"/> over its owned versions.
    /// </summary>
    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }

    /// <summary>
    /// Filter-only: matches if any entry in <see cref="Platforms"/> has this platform. Never persisted -
    /// this property exists solely so <see cref="VideoGameModel"/> can keep doubling as the filter-probe
    /// object passed to <c>IDataRepository{TModel}.FindAllAsync</c>, the same convention every other
    /// repository already relies on.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Filter-only: matches if any entry in <see cref="Platforms"/> has this state. Never persisted - see
    /// <see cref="Platform"/>.
    /// </summary>
    public string? State { get; set; }
}
