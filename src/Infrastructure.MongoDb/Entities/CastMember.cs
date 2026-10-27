using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded in <see cref="TvShowReference"/> and <see cref="MovieReference"/> (see <see cref="Keeptrack.Domain.Models.CastMemberModel"/> for why).
/// </summary>
public class CastMember
{
    [BsonElement("person_reference_id")]
    public required string PersonReferenceId { get; set; }

    [BsonElement("character_name")]
    public required string CharacterName { get; set; }

    public int Order { get; set; }
}
