using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A piece of gear/equipment the user owns (e.g. a TV, a bike, a keyboard).
/// </summary>
public class GearDto : IHasId
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Gear name.
    /// </summary>
    /// <example>Standing desk</example>
    public string? Title { get; set; }

    /// <summary>
    /// Brand or manufacturer.
    /// </summary>
    /// <example>Sony</example>
    public string? Brand { get; set; }

    /// <summary>
    /// Year.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>
    /// Free-text notes (where it's stored, where it's used, or any other specifics).
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this item - it counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version. Never populated on a
    /// returned item - see <see cref="VideoGameDto.Platform"/> for the convention.
    /// </summary>
    public bool IsOwned { get; set; }
}
