using System;

namespace KeepTrack.WebApi.Dto;

/// <summary>
/// Video Game data transfer object.
/// </summary>
public class VideoGameDto
{
    /// <summary>
    /// Video Game ID.
    /// </summary>
    public string Id { get; set; }

    /// <summary>
    /// Video Game title.
    /// </summary>
    public string Title { get; set; }

    /// <summary>
    /// Latest plaform the game has been played on.
    /// </summary>
    public string Platform { get; set; }

    /// <summary>
    /// Released date.
    /// </summary>
    public DateTime? ReleasedAt { get; set; }

    /// <summary>
    /// Current payling state.
    /// </summary>
    public string State { get; set; }

    /// <summary>
    /// Finished date.
    /// </summary>
    public DateTime? FinishedAt { get; set; }
}
