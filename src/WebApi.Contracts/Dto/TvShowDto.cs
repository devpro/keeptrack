using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// TV Show history transfer object.
/// </summary>
public class TvShowDto : IHasId
{
    /// <summary>
    /// TV Show ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// TV Show title.
    /// </summary>
    public string? Title { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? LastEpisodeSeen { get; set; }

    public string? ImdbPageId { get; set; }

    public string? AllocineId { get; set; }

    public DateOnly? FinishedAt { get; set; }
}
