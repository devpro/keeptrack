using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Playthrough
{
    public required string Label { get; set; }

    [BsonElement("completed_at")]
    public DateTime? CompletedAt { get; set; }
}
