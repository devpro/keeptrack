using System;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
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

    public required string City { get; set; }

    [BsonElement("property_type")]
    public required PropertyType PropertyType { get; set; }

    [BsonElement("moved_in_at")]
    public DateTime? MovedInAt { get; set; }

    [BsonElement("moved_out_at")]
    public DateTime? MovedOutAt { get; set; }

    public string? Notes { get; set; }

    [BsonElement("image_url")]
    public string? ImageUrl { get; set; }
}
