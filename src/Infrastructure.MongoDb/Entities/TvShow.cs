using System.Collections.Generic;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class TvShow : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    [BsonElement("tv_time_id")]
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    [BsonElement("last_episode_seen")]
    public string? LastEpisodeSeen { get; set; }

    [BsonElement("reference_id")]
    public string? ReferenceId { get; set; }

    // storage name kept as "status" deliberately - only the C# property was renamed to State (for parity
    // with VideoGame.State), so existing documents need no migration.
    [BsonElement("status")]
    public TvShowStatus? State { get; set; }

    [BsonElement("is_favorite")]
    public bool IsFavorite { get; set; }

    [BsonElement("want_to_watch")]
    public bool WantToWatch { get; set; }

    [BsonElement("owned_versions")]
    public List<OwnedVersion> OwnedVersions { get; set; } = [];

    [BsonElement("is_wishlisted")]
    public bool IsWishlisted { get; set; }
}
