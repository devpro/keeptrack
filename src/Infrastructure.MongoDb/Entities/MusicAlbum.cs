using Keeptrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class MusicAlbum : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Artist { get; set; }

    public int? Year { get; set; }

    public string? Genre { get; set; }

    public float? Rating { get; set; }
}
