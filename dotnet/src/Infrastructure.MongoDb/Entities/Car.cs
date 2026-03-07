using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Infrastructure.MongoDb.Entities;

public class Car : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("commercial_name")]
    public required string Name { get; set; }
}
