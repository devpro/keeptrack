using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class VideoGameModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public List<VideoGamePlatformModel> Platforms { get; set; } = [];

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? ReferenceId { get; set; }

    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }

    /// <summary>
    /// Filter-only: matches if any entry in <see cref="Platforms"/> has this platform. Never persisted -
    /// this property exists solely so <see cref="VideoGameModel"/> can keep doubling as the filter-probe
    /// object passed to <c>IDataRepository{TModel}.FindAllAsync</c>, the same convention every other
    /// repository already relies on.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Filter-only: matches if any entry in <see cref="Platforms"/> has this state. Never persisted - see
    /// <see cref="Platform"/>.
    /// </summary>
    public string? State { get; set; }
}
