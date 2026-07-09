using System;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class HouseHistory : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("house_id")]
    public required string HouseId { get; set; }

    [BsonElement("history_date")]
    public required DateTime HistoryDate { get; set; }

    [BsonElement("event_type")]
    public required HouseEventType EventType { get; set; }

    public string? Description { get; set; }

    public double? Cost { get; set; }

    public string? Provider { get; set; }
}
