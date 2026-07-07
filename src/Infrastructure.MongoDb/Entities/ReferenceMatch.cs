namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded within <see cref="TvShowReference"/>/<see cref="MovieReference"/> - see
/// <see cref="Keeptrack.Domain.Models.ReferenceMatchModel"/> for why embedding is the right call here.
/// </summary>
public class ReferenceMatch
{
    public required string Title { get; set; }

    public int? Year { get; set; }
}
