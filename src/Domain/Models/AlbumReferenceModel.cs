using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, tenant-agnostic album metadata sourced from an external provider (Discogs).
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class AlbumReferenceModel : IHasId
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// Points at the shared, deduplicated <see cref="PersonReferenceModel"/> for this album's artist
    /// (keyed by the artist's Discogs id) - the same dedup mechanism as TV/movie cast, just for a single
    /// credited individual/group instead of a list. Null when Discogs' response didn't carry an artist id
    /// to dedupe by.
    /// </summary>
    public string? ArtistReferenceId { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination that has ever been confirmed to mean this album - see
    /// <see cref="TvShowReferenceModel.MatchedAliases"/> for the full rationale.
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<ReferenceTrackModel> Tracks { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
