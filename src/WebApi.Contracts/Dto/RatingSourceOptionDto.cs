using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A domain whose primary rating source an admin can choose, with its selectable sources and the selected one (see <c>GET /api/reference-data/rating-sources</c>).
/// </summary>
public class RatingSourceOptionDto
{
    /// <summary>The domain this option applies to, such as video games.</summary>
    public ReferenceItemType Domain { get; set; }

    /// <summary>The source keys selectable as primary for this domain, such as "igdb" and "igdbcritic".</summary>
    public required List<string> AvailableSources { get; set; }

    /// <summary>The source used as primary: the admin's choice, or the default when none is set.</summary>
    public required string SelectedSource { get; set; }
}
