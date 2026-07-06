using System;
using Keeptrack.Common.System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Episode : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("tv_show_id")]
    public required string TvShowId { get; set; }

    [BsonElement("season_number")]
    public required int SeasonNumber { get; set; }

    [BsonElement("episode_number")]
    public required int EpisodeNumber { get; set; }

    [BsonElement("watched_at")]
    public DateTime? WatchedAt { get; set; }

    public string? Notes { get; set; }
}
