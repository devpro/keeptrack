namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// The copy of the linked reference's primary rating that every reference-linked type carries under the same names.
/// An interface, so the queries over it are written once (<see cref="Repositories.ReferenceRatingQueries"/>) rather than per entity, more simply than passing field expressions.
/// </summary>
public interface IHasReferenceRating
{
    string? ReferenceId { get; set; }

    double? ReferenceRating { get; set; }

    double? ReferenceRatingScale { get; set; }

    /// <summary>The rating source the two values above were computed from (see <c>RatingSourceCatalog</c>).</summary>
    string? ReferenceRatingSource { get; set; }
}
