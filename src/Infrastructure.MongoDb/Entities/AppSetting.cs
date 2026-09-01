using System.Collections.Generic;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// The single global-settings document (see <see cref="Repositories.AppSettingRepository"/>). One shared
/// collection holds every admin-configurable global setting as its own field, rather than a collection per
/// setting - a new setting is a new field here.
/// </summary>
public class AppSetting
{
    /// <summary>Well-known fixed id of the one settings document.</summary>
    [BsonId]
    public required string Id { get; set; }

    /// <summary>Domain key (e.g. <c>VideoGame</c>) → primary rating source key (e.g. <c>metacritic</c>).</summary>
    [BsonElement("reference_rating_source")]
    public Dictionary<string, string> ReferenceRatingSources { get; set; } = new();

    /// <summary>
    /// When true, the Explore discovery feature ranks/shows TMDB ratings for movies and TV shows even when
    /// IMDb is the selected primary rating source - avoiding a per-title OMDb lookup on every page load.
    /// Defaults to false (Explore follows the primary source).
    /// </summary>
    [BsonElement("explore_use_tmdb")]
    public bool ExploreUseTmdb { get; set; }
}
