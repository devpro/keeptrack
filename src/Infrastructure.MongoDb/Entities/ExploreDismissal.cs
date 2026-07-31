using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One owner's "don't suggest this again" record for the Explore feature (<c>explore_dismissal</c>). The
/// natural key is (owner_id, item_type, external_source, external_id); see <see cref="ExploreDismissalModel"/>.
/// </summary>
public class ExploreDismissal
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    // stored as its enum member name via the registered EnumRepresentationConvention(BsonType.String).
    [BsonElement("item_type")]
    public required ExploreItemType ItemType { get; set; }

    [BsonElement("external_source")]
    public required string ExternalSource { get; set; }

    [BsonElement("external_id")]
    public required string ExternalId { get; set; }
}
