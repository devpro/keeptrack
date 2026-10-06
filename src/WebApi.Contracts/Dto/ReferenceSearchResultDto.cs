using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One provider search candidate, shown to an admin picking the match for an unresolved title.
/// Cover art and top cast names (TV and movies) help tell near-identical candidates apart, such as remakes and regional variants.
/// </summary>
public class ReferenceSearchResultDto
{
    public required string ExternalId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? ImageUrl { get; set; }

    /// <summary>
    /// Book author or album artist, null for the other domains, where TV and movies show <see cref="TopCastNames"/> instead.
    /// </summary>
    public string? Creator { get; set; }

    public List<string> TopCastNames { get; set; } = [];
}
