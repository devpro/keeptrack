using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded aggregate rating from a single source, the value type of a reference entity's <c>ratings</c>
/// map (keyed by source name). See <see cref="Keeptrack.Domain.Models.ReferenceRatingModel"/>.
/// </summary>
public class ReferenceRating
{
    public required double Value { get; set; }

    public required double Scale { get; set; }

    public int? Count { get; set; }
}
