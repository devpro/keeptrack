using System.Collections.Generic;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// The single global-settings document (see <see cref="Repositories.AppSettingRepository"/>).
/// Every global admin setting is a field of this one document, so a new setting is a new field here, never a new collection.
/// </summary>
public class AppSetting
{
    /// <summary>The fixed id of the one settings document.</summary>
    [BsonId]
    public required string Id { get; set; }

    /// <summary>Domain key (<c>VideoGame</c>) to primary rating source key (<c>igdb</c>).</summary>
    [BsonElement("reference_rating_source")]
    public Dictionary<string, string> ReferenceRatingSources { get; set; } = new();

    /// <summary>
    /// When true, Explore shows TMDB ratings for movies and TV shows even when IMDb is the primary source, avoiding an OMDb lookup per title.
    /// False by default, Explore then following the primary source.
    /// </summary>
    [BsonElement("explore_use_tmdb")]
    public bool ExploreUseTmdb { get; set; }
}
