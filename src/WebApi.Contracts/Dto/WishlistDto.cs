using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Everything wishlisted across every trackable type, in one place.
/// </summary>
public class WishlistDto
{
    public List<MovieDto> Movies { get; set; } = [];

    public List<TvShowDto> TvShows { get; set; } = [];

    public List<BookDto> Books { get; set; } = [];

    public List<VideoGameDto> VideoGames { get; set; } = [];
}
