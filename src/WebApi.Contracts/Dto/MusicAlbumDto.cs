using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

public class MusicAlbumDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public string? Artist { get; set; }

    public int? Year { get; set; }

    public string? Genre { get; set; }

    public float? Rating { get; set; }
}
