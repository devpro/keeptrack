using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Dal.MongoDb.Entities;

public class VideoGame : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public string OwnerId { get; set; }

    public string Title { get; set; }

    public string Platform { get; set; }

    [BsonElement("released_at")]
    public DateTime? ReleasedAt { get; set; }

    public string State { get; set; }

    [BsonElement("finished_at")]
    public DateTime? FinishedAt { get; set; }
}
