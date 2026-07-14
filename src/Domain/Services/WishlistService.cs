using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Assembles the cross-type wishlist view: each list is expected to already be filtered to <c>IsWishlisted == true</c> by the repository query (see <c>WishlistController</c>),
/// so this only sorts each type's results alphabetically by title for a stable, scannable display order.
/// </summary>
public static class WishlistService
{
    public static List<MovieModel> SortMovies(IEnumerable<MovieModel> movies) =>
        movies.OrderBy(m => m.Title).ToList();

    public static List<TvShowModel> SortTvShows(IEnumerable<TvShowModel> tvShows) =>
        tvShows.OrderBy(s => s.Title).ToList();

    public static List<BookModel> SortBooks(IEnumerable<BookModel> books) =>
        books.OrderBy(b => b.Title).ToList();

    public static List<VideoGameModel> SortVideoGames(IEnumerable<VideoGameModel> videoGames) =>
        videoGames.OrderBy(g => g.Title).ToList();
}
