using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded within <see cref="TvShowReference"/>/<see cref="MovieReference"/> - see
/// <see cref="Keeptrack.Domain.Models.CastMemberModel"/> for the embedding rationale.
/// </summary>
public class CastMember
{
    [BsonElement("person_reference_id")]
    public required string PersonReferenceId { get; set; }

    [BsonElement("character_name")]
    public required string CharacterName { get; set; }

    public int Order { get; set; }
}
