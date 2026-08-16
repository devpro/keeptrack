using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class VideoGameModel : IHasIdAndOwnerId, IReferenceLinkedModel
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
    /// Denormalized copy of the linked reference's primary-source (RAWG) 0-5 rating, on
    /// <see cref="ReferenceRatingScale"/>. Copied down on link/refresh for fast list display and sorting;
    /// the authoritative multi-source data (RAWG + Metacritic) is on <see cref="VideoGameReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for RAWG); null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// Which rating source <see cref="ReferenceRating"/> was taken from ("tmdb", "imdb", "rawg", ...) - see
    /// <c>RatingSourceCatalog</c>. Stamped on every link/refresh, and stamped even when that source has no
    /// value for this reference: it records which source the denormalized copy was computed from, not where a
    /// number came from, which is what lets the admin "recompute" action tell an item that is already on the
    /// selected source from one that still needs re-stamping. Null only for items linked before this existed.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

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
