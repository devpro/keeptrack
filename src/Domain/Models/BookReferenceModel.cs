using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, tenant-agnostic book metadata sourced from an external provider (Open Library).
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class BookReferenceModel : IHasId
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// Points at the shared, deduplicated <see cref="PersonReferenceModel"/> for this book's author
    /// (keyed by the author's Open Library id) - the same dedup mechanism as TV/movie cast, just for a
    /// single credited individual instead of a list. Null when Open Library's response didn't carry an
    /// author id to dedupe by.
    /// </summary>
    public string? AuthorReferenceId { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination that has ever been confirmed to mean this book - see
    /// <see cref="TvShowReferenceModel.MatchedAliases"/> for the full rationale.
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
