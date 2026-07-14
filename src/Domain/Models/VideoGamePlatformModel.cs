using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One entry per platform a game is tracked on for a given tenant - not one entry per physical copy.
/// Owning two PS5 discs of the same game is still a single entry with <see cref="Platform"/> "PS5".
/// <see cref="IsFullyCompleted"/>/<see cref="FullyCompletedAt"/> ("platinum"/100%) live here rather than
/// on <see cref="VideoGameModel"/> or on a single <see cref="Playthroughs"/> entry, because full
/// completion is a per-platform fact - a PS5 platinum says nothing about Xbox/PC progress on the same game.
/// </summary>
public class VideoGamePlatformModel
{
    public required string Platform { get; set; }

    public VideoGameCopyType CopyType { get; set; }

    public string State { get; set; } = "";

    public List<PlaythroughModel> Playthroughs { get; set; } = [];

    public bool IsFullyCompleted { get; set; }

    public DateOnly? FullyCompletedAt { get; set; }
}
