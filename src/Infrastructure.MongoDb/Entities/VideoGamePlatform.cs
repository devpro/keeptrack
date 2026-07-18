using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class VideoGamePlatform
{
    public required string Platform { get; set; }

    [BsonElement("copy_type")]
    public CopyType CopyType { get; set; }

    public string State { get; set; } = "";

    [BsonElement("completed_at")]
    public DateTime? CompletedAt { get; set; }

    public List<Playthrough> Playthroughs { get; set; } = [];

    [BsonElement("is_fully_completed")]
    public bool IsFullyCompleted { get; set; }

    [BsonElement("fully_completed_at")]
    public DateTime? FullyCompletedAt { get; set; }

    [BsonRepresentation(BsonType.Decimal128)]
    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    [BsonElement("acquired_at")]
    public DateTime? AcquiredAt { get; set; }

    public string? Reference { get; set; }
}
