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
    /// here or anywhere else in the codebase. What previously defeated that convention for this property
    /// specifically was AutoMapper's profile-wide <c>AllowNullDestinationValues = false</c> (Program.cs)
    /// substituting an empty string for the null *before* BSON serialization ever saw it - fixed at the
    /// mapping layer instead (<c>DataStorageMappingProfile</c>'s per-member <c>.ForMember(x => x.Creator,
    /// opt => opt.AllowNull())</c>), so the value reaching the (already-correct) Mongo convention is a real
    /// null again.
    /// </summary>
    public string? Creator { get; set; }
}
