using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class MusicAlbumModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Artist { get; set; }

    public int? Year { get; set; }

    public string? Genre { get; set; }

    public float? Rating { get; set; }
}
