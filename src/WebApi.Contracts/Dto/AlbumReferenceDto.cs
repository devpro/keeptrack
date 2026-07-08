using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Shared album metadata (synopsis, cover) - read-only, fetched separately from <see cref="AlbumDto"/> since
/// it isn't the tenant's own data.
/// </summary>
public class AlbumReferenceDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? ArtistName { get; set; }

    public string? ArtistImageUrl { get; set; }

    public List<string> Genres { get; set; } = [];

    public List<ReferenceTrackDto> Tracks { get; set; } = [];

    public string? ImageUrl { get; set; }
}
