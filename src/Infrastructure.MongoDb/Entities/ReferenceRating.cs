using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// An embedded aggregate rating from one source, the value type of a reference entity's <c>ratings</c> map.
/// See <see cref="Keeptrack.Domain.Models.ReferenceRatingModel"/>.
/// </summary>
public class ReferenceRating
{
    public required double Value { get; set; }

    public required double Scale { get; set; }

    public int? Count { get; set; }
}
