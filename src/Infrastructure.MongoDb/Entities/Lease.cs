using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One named distributed lease (see <see cref="Repositories.LeaseRepository"/>).
/// Acquisition stays in infrastructure, and only the diagnostic read maps to <c>LeaseModel</c>, by hand, since three read-only fields do not warrant a generated mapper.
/// </summary>
public class Lease
{
    /// <summary>The lease name, one document per lease, unique as the _id.</summary>
    [BsonId]
    public required string Id { get; set; }

    public required string Holder { get; set; }

    [BsonElement("expires_at")]
    public DateTime ExpiresAt { get; set; }
}
