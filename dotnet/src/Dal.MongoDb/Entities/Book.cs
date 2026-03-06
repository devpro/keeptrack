using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Dal.MongoDb.Entities;

public class Book : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public string OwnerId { get; set; }

    public string Title { get; set; }

    public string Author { get; set; }

    public string Series { get; set; }

    [BsonElement("finished_at")]
    public DateTime? FinishedAt { get; set; }
}
