using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Dal.MongoDb.Entities;

public class Car : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public string OwnerId { get; set; }

    [BsonElement("commercial_name")]
    public string Name { get; set; }
}
