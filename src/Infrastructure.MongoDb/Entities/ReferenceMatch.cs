namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded within <see cref="TvShowReference"/>/<see cref="MovieReference"/> - see
/// <see cref="Keeptrack.Domain.Models.ReferenceMatchModel"/> for why embedding is the right call here.
/// </summary>
public class ReferenceMatch
{
    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>
    /// Null for TV show/movie/video game (no creator dimension in their match key). The global
    /// <c>IgnoreIfNullConvention</c> (<c>InfrastructureServiceCollectionExtensions.AddMongoDbInfrastructure</c>)
    /// already omits any null property from the document - no per-property <c>[BsonIgnoreIfNull]</c> needed
    /// here or anywhere else in the codebase. This used to require a per-member AutoMapper opt-out
    /// (<c>.ForMember(x => x.Creator, opt => opt.AllowNull())</c>) because AutoMapper's profile-wide
    /// <c>AllowNullDestinationValues = false</c> substituted an empty string for the null before BSON
    /// serialization ever saw it; Mapperly (the current mapper, see <c>ReferenceMatchModel</c> ->
    /// <c>ReferenceMatch</c> mapping in <c>TvShowReferenceStorageMapper</c> etc.) preserves nulls by
    /// default, so no such opt-out exists or is needed anymore. Historical documents written under the
    /// old behavior still store <c>""</c> instead of an absent field - see <c>MergeMatchedAliases</c>.
    /// </summary>
    public string? Creator { get; set; }

    /// <summary>Null for every domain but Book - see <see cref="Keeptrack.Domain.Models.ReferenceMatchModel.Isbn"/>.</summary>
    public string? Isbn { get; set; }
}
