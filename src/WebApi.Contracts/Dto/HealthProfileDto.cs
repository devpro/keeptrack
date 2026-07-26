using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Health profile data transfer object - whose health journal this is.
/// </summary>
public class HealthProfileDto : IHasId
{
    /// <summary>
    /// Health profile ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The person's name (e.g. "Me", a child's first name).
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Free-text notes (blood type, allergies, anything worth keeping at hand).
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }
}
