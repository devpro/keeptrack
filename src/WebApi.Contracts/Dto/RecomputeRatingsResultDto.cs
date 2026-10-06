namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of applying a domain's primary rating source again to every linked tenant item (see <c>POST /api/reference-data/rating-sources/{domain}/recompute</c>).
/// </summary>
public class RecomputeRatingsResultDto
{
    /// <summary>How many reference documents were read and copied again.</summary>
    public int ReferencesChecked { get; set; }

    /// <summary>How many tenant items had their rating copy updated.</summary>
    public long ItemsUpdated { get; set; }
}
