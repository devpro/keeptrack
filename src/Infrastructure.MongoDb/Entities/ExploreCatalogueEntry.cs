using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One entry of a materialized provider ranking (<c>explore_catalogue</c>). Shared and owner-less, like the
/// <c>*_reference</c> collections - see <see cref="ExploreCatalogueEntryModel"/> for why. Natural key is
/// (item_type, ranking, external_id), unique in the database.
/// </summary>
public class ExploreCatalogueEntry
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    // stored as its enum member name via the registered EnumRepresentationConvention(BsonType.String).
    [BsonElement("item_type")]
    public required ExploreItemType ItemType { get; set; }

    [BsonElement("ranking")]
    public required string Ranking { get; set; }

    [BsonElement("external_id")]
    public required string ExternalId { get; set; }

    [BsonElement("rank")]
    public required int Rank { get; set; }

    [BsonElement("title")]
    public required string Title { get; set; }

    [BsonElement("year")]
    public int? Year { get; set; }

    [BsonElement("synopsis")]
    public string? Synopsis { get; set; }

    [BsonElement("image_url")]
    public string? ImageUrl { get; set; }

    /// <summary>Rating value per source key ("tmdb"/"imdb", "rawg"/"metacritic") - merged per key on refresh, never replaced.</summary>
    [BsonElement("ratings")]
    public Dictionary<string, double> Ratings { get; set; } = [];

    /// <summary>When each rating source was last attempted, successful or not - see <see cref="ExploreCatalogueEntryModel.RatingsCheckedAt"/>.</summary>
    [BsonElement("ratings_checked_at")]
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    [BsonElement("refreshed_at")]
    public DateTime RefreshedAt { get; set; }
}
