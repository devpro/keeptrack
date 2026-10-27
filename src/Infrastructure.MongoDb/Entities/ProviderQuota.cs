using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One day's call count for one rate-limited provider (see <see cref="Repositories.ProviderQuotaRepository"/>).
/// Like <see cref="Lease"/>, the _id is the coordination: "&lt;provider&gt;:&lt;yyyy-MM-dd&gt;" is unique,
/// so another replica's concurrent reservation increments this document or collides with it, never creating a second counter for the day.
/// </summary>
public class ProviderQuota
{
    /// <summary>"&lt;provider&gt;:&lt;UTC yyyy-MM-dd&gt;", unique as the _id.</summary>
    [BsonId]
    public required string Id { get; set; }

    [BsonElement("used")]
    public int Used { get; set; }

    /// <summary>Set once, on insert, for the TTL index that purges past counters.</summary>
    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; }
}
