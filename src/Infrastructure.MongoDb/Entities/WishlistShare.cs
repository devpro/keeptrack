using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class WishlistShare
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Token { get; set; }
}
