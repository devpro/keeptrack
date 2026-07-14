using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Shared, owner-less person/actor metadata collection (<c>person_reference</c>). See
/// <see cref="Keeptrack.Domain.Models.PersonReferenceModel"/> for why this has no <c>owner_id</c>.
/// </summary>
public class PersonReference
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public required string Name { get; set; }

    [BsonElement("profile_image_url")]
    public string? ProfileImageUrl { get; set; }

    [BsonElement("external_ids")]
    public required Dictionary<string, string> ExternalIds { get; set; }
}
