namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// The denormalized copy of a linked reference document's primary rating that every trackable type carries
/// identically. Declared as an interface purely so the queries over it can be written once
/// (<see cref="Repositories.ReferenceRatingQueries"/>) instead of five times over five entity types - the
/// same motivation as <see cref="Repositories.ExploreExclusionQueries"/>' field expressions, but here the
/// four fields are named identically everywhere, so an interface is simpler than passing four lambdas.
/// </summary>
public interface IHasReferenceRating
{
    string? ReferenceId { get; set; }

    double? ReferenceRating { get; set; }

    double? ReferenceRatingScale { get; set; }

    /// <summary>Which rating source the two values above were computed from - see <c>RatingSourceCatalog</c>.</summary>
    string? ReferenceRatingSource { get; set; }
}
