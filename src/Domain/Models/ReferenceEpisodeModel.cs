using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One episode's reference metadata (title, air date), embedded in a <see cref="TvShowReferenceModel"/>.
/// The tenant's <see cref="EpisodeModel"/> is a separate collection, since it grows without bound and Watch Next queries it across shows.
/// This list is bounded by the show's real runtime and always fetched whole, so it is embedded.
/// </summary>
public class ReferenceEpisodeModel
{
    public required int SeasonNumber { get; set; }

    public required int EpisodeNumber { get; set; }

    public required string Title { get; set; }

    public DateOnly? AirDate { get; set; }
}
