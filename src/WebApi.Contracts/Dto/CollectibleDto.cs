using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A collectible the user owns, such as a Lego set or a figurine.
/// </summary>
public class CollectibleDto : IHasId
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Collectible name.
    /// </summary>
    /// <example>Millennium Falcon</example>
    public string? Title { get; set; }

    /// <summary>
    /// Brand or manufacturer.
    /// </summary>
    /// <example>Lego</example>
    public string? Brand { get; set; }

    /// <summary>
    /// Year.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>
    /// Free-text notes: where it is stored or displayed, or any other specifics.
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// The tenant's own optional cover image URL, shown on the list thumbnail and the detail page header.
    /// </summary>
    public string? ImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this item, which counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version.
    /// Never set on a returned item (see <see cref="VideoGameDto.Platform"/>).
    /// </summary>
    public bool IsOwned { get; set; }
}
