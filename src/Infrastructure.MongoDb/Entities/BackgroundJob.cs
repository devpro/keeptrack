using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class BackgroundJob
{
    /// <summary>The job's Guid as a plain string, which avoids configuring the BSON Guid representation.</summary>
    [BsonId]
    public required string Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Kind { get; set; }

    public required string Stage { get; set; }

    [BsonElement("result_json")]
    public string? ResultJson { get; set; }

    [BsonElement("error_message")]
    public string? ErrorMessage { get; set; }

    /// <summary>Drives the TTL index that purges finished jobs (see <c>scripts/mongodb-create-index.js</c>).</summary>
    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; }
}
