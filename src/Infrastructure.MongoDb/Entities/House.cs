using Keeptrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class House : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Name { get; set; }

    public string? Address { get; set; }

    public string? City { get; set; }

    [BsonElement("postal_code")]
    public string? PostalCode { get; set; }

    public string? Country { get; set; }

    public string? Notes { get; set; }
}
