using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// House data transfer object.
/// </summary>
public class HouseDto : IHasId
{
    /// <summary>
    /// House ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// House name (e.g. "Main house", "Beach apartment").
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// City.
    /// </summary>
    public string? City { get; set; }

    /// <summary>
    /// Type of property (house, apartment, or other).
    /// </summary>
    public PropertyType? PropertyType { get; set; }

    /// <summary>
    /// When the owner moved into this property, if recorded.
    /// </summary>
    public DateOnly? MovedInAt { get; set; }

    /// <summary>
    /// When the owner moved out of this property, if recorded (unset while still occupied).
    /// </summary>
    public DateOnly? MovedOutAt { get; set; }

    /// <summary>
    /// Free-text notes.
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }
}
