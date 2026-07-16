using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One named distributed lease (see <see cref="Repositories.LeaseRepository"/>). The acquisition path is
/// purely an infrastructure concern; only the diagnostic read maps out to <c>LeaseModel</c> (by hand -
/// three read-only fields don't warrant a generated mapper).
/// </summary>
public class Lease
{
    /// <summary>The lease name - one document per lease, uniqueness enforced by _id itself.</summary>
    [BsonId]
    public required string Id { get; set; }

    public required string Holder { get; set; }

    [BsonElement("expires_at")]
    public DateTime ExpiresAt { get; set; }
}
