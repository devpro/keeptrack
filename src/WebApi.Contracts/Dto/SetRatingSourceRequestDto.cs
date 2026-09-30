namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Sets a domain's primary rating source - see <c>PUT /api/reference-data/rating-sources/{domain}</c>.
/// </summary>
public class SetRatingSourceRequestDto
{
    /// <summary>The source key to make primary; must be one of the domain's available sources.</summary>
    public required string Source { get; set; }
}
