using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A domain whose primary rating source an admin can choose, plus its selectable sources and the currently
/// selected one - see <c>GET /api/reference-data/rating-sources</c>.
/// </summary>
public class RatingSourceOptionDto
{
    /// <summary>The domain this option applies to (e.g. video games).</summary>
    public ReferenceItemType Domain { get; set; }

    /// <summary>The source keys that can be picked as primary for this domain, e.g. "rawg"/"metacritic".</summary>
    public required List<string> AvailableSources { get; set; }

    /// <summary>The source currently used as primary - the admin override, or the code default when none is set.</summary>
    public required string SelectedSource { get; set; }
}
