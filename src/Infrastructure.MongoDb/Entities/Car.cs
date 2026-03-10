using Keeptrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Car : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("commercial_name")]
    public required string Name { get; set; }
}
