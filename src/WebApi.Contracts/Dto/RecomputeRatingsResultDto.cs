namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of re-applying a domain's primary rating source to every linked tenant item - see
/// <c>POST /api/reference-data/rating-sources/{domain}/recompute</c>.
/// </summary>
public class RecomputeRatingsResultDto
{
    /// <summary>How many reference documents were read and re-propagated.</summary>
    public int ReferencesChecked { get; set; }

    /// <summary>How many tenant items had their denormalized rating scalar updated.</summary>
    public long ItemsUpdated { get; set; }
}
