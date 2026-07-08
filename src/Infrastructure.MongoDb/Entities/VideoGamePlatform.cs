using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class VideoGamePlatform
{
    public required string Platform { get; set; }

    [BsonElement("copy_type")]
    public VideoGameCopyType CopyType { get; set; }

    public string State { get; set; } = "";

    public List<Playthrough> Playthroughs { get; set; } = [];

    [BsonElement("is_fully_completed")]
    public bool IsFullyCompleted { get; set; }

    [BsonElement("fully_completed_at")]
    public DateTime? FullyCompletedAt { get; set; }
}
