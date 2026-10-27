using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Whose health journal this is.
/// </summary>
public class HealthProfileDto : IHasId
{
    /// <summary>
    /// Health profile ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The person's name, such as "Me" or a child's first name.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Free-text notes: blood type, allergies, anything worth keeping at hand.
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// The tenant's own optional cover image URL, shown on the list thumbnail and the detail page header.
    /// </summary>
    public string? ImageUrl { get; set; }
}
