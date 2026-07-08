using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Playlist data transfer object.
/// </summary>
public class PlaylistDto : IHasId
{
    /// <summary>
    /// Playlist ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Playlist title.
    /// </summary>
    public string? Title { get; set; }

    /// <summary>
    /// Ids of the songs in this playlist, in playback order.
    /// </summary>
    public List<string> SongIds { get; set; } = [];
}
