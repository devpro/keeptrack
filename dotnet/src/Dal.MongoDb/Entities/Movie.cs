using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Dal.MongoDb.Entities;

public class Movie : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public string OwnerId { get; set; }

    public string Title { get; set; }

    public int? Year { get; set; }

    public Imdb Imdb { get; set; }

    public Allocine Allocine { get; set; }
}
