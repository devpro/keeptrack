using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class PlaylistModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// Ids of <see cref="SongModel"/> documents, in playback order - the list's own order is the
    /// playlist order, there's no separate position field.
    /// </summary>
    public List<string> SongIds { get; set; } = [];
}
