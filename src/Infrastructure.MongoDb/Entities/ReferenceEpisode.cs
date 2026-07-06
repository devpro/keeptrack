using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded within <see cref="TvShowReference"/> - see that class for why embedding is the right call here.
/// </summary>
public class ReferenceEpisode
{
    [BsonElement("season_number")]
    public required int SeasonNumber { get; set; }

    [BsonElement("episode_number")]
    public required int EpisodeNumber { get; set; }

    public required string Title { get; set; }

    [BsonElement("air_date")]
    public DateTime? AirDate { get; set; }
}
