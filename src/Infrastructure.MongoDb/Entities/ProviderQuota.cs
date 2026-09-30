using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One day's call count for one rate-limited provider (see <see cref="Repositories.ProviderQuotaRepository"/>).
/// Like <see cref="Lease"/>, the whole coordination mechanism is the _id: "&lt;provider&gt;:&lt;yyyy-MM-dd&gt;"
/// is unique by definition, so a concurrent reservation from another replica either increments this document
/// or collides with it - never a second counter for the same day.
/// </summary>
public class ProviderQuota
{
    /// <summary>"&lt;provider&gt;:&lt;UTC yyyy-MM-dd&gt;" - uniqueness enforced by _id itself.</summary>
    [BsonId]
    public required string Id { get; set; }

    [BsonElement("used")]
    public int Used { get; set; }

    /// <summary>Set once, on insert - drives the TTL index that purges yesterday's counters.</summary>
    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; }
}
