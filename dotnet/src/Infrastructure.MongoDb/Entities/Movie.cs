using KeepTrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Infrastructure.MongoDb.Entities;

public class Movie : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public int? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Notes { get; set; }

    public Imdb? Imdb { get; set; }

    public Allocine? Allocine { get; set; }
}
