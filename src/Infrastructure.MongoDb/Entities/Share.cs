using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Share
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("owner_display_name")]
    public string? OwnerDisplayName { get; set; }

    [BsonElement("recipient_email")]
    public required string RecipientEmail { get; set; }

    // stored as their string member names via the registered EnumRepresentationConvention(BsonType.String)
    [BsonElement("included_categories")]
    public List<ShareCategory> IncludedCategories { get; set; } = [];

    public string? Label { get; set; }

    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; }
}
