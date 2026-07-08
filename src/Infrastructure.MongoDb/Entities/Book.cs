using System;
using Keeptrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Book : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Author { get; set; }

    public string? Series { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Notes { get; set; }

    [BsonElement("first_read_at")]
    public DateTime? FirstReadAt { get; set; }

    [BsonElement("reference_id")]
    public string? ReferenceId { get; set; }

    [BsonElement("is_favorite")]
    public bool IsFavorite { get; set; }

    [BsonElement("is_owned")]
    public bool IsOwned { get; set; }

    [BsonElement("is_wishlisted")]
    public bool IsWishlisted { get; set; }
}
