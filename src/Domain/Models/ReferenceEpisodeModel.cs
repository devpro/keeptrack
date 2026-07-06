using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One episode's reference metadata (title, air date), embedded within a <see cref="TvShowReferenceModel"/>.
/// Unlike the per-tenant <see cref="EpisodeModel"/> (a separate collection, since it grows unbounded per
/// user over years and is queried across shows for Watch Next), this list is bounded to one show's real
/// runtime and always fetched as a whole, so embedding is the right call here.
/// </summary>
public class ReferenceEpisodeModel
{
    public required int SeasonNumber { get; set; }

    public required int EpisodeNumber { get; set; }

    public required string Title { get; set; }

    public DateOnly? AirDate { get; set; }
}
