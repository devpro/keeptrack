using System;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded in <see cref="TvShowReference"/> (see <see cref="Keeptrack.Domain.Models.ReferenceEpisodeModel"/> for why).
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
