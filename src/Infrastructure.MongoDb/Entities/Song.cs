using Keeptrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Song : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public string? Artist { get; set; }

    [BsonElement("album_id")]
    public string? AlbumId { get; set; }

    public string? Duration { get; set; }

    [BsonElement("track_position")]
    public string? TrackPosition { get; set; }
}
