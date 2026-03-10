using System;
using KeepTrack.Common.System;

namespace KeepTrack.Domain.Models;

public class VideoGameModel : IHasIdAndOwnerId
{
    public string Id { get; set; } = string.Empty;

    public string OwnerId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Platform { get; set; } = string.Empty;

    public DateTime? ReleasedAt { get; set; }

    public string State { get; set; } = string.Empty;

    public DateTime? FinishedAt { get; set; }
}
