using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Infrastructure.MongoDb.Entities;

public class Movie : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public Imdb? Imdb { get; set; }

    public Allocine? Allocine { get; set; }
}
