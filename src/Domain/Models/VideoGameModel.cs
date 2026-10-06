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
    /// The linked reference's primary rating, from the source the admin selected, on <see cref="ReferenceRatingScale"/>.
    /// Copied on link and refresh so a list displays and sorts without a join.
    /// The authoritative data is <see cref="VideoGameReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/>, null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> was taken from, a <c>RatingSourceCatalog</c> key ("tmdb", "imdb", "igdb").
    /// Stamped on every link and refresh, even when that source has no value for this reference.
    /// It records which source the copy was computed from, which is how the admin recompute tells an item already on the selected source from one needing a new stamp.
    /// Null on an item never stamped, which the recompute counts as different.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    /// <summary>
    /// The tenant's own cover, which takes priority over the linked reference's cover wherever a cover is shown (list thumbnail, detail page).
    /// Null means the reference's cover, if any.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    /// <summary>
    /// Filter only: matches when <see cref="Platforms"/> is non-empty.
    /// Never persisted: a platform entry is this type's owned copy, so ownership derives from having one, as <see cref="MovieModel.IsOwned"/> does from owned versions.
    /// </summary>
    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }

    /// <summary>
    /// Filter only: matches when any entry in <see cref="Platforms"/> has this platform.
    /// Never persisted: it exists so the model doubles as the filter probe passed to <c>IDataRepository{TModel}.FindAllAsync</c>, as every repository does.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Filter only: matches when any entry in <see cref="Platforms"/> has this state.
    /// Never persisted (see <see cref="Platform"/>).
    /// </summary>
    public string? State { get; set; }
}
