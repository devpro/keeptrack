using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, owner-less actor/person metadata sourced from an external provider such as TMDB. Deduplicated
/// across every show/movie that credits them - matched by external provider id, not by name (unlike
/// <see cref="TvShowReferenceModel"/>/<see cref="MovieReferenceModel"/>, credits already give an exact id).
/// </summary>
public class PersonReferenceModel : IHasId
{
    public string? Id { get; set; }

    public required string Name { get; set; }

    public string? ProfileImageUrl { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }
}
