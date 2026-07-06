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

    /// <summary>
    /// Id of the shared reference-data document (episode titles, synopsis) for this show, once resolved.
    /// </summary>
    public string? ReferenceId { get; set; }

    public DateOnly? FinishedAt { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }
}
