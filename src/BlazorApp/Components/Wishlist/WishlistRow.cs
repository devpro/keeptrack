using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Wishlist;

/// <summary>
/// The one common projection all four wishlisted item types share - a single row loop instead of four
/// near-identical per-type markup blocks, used by both the owner's tabbed page (<c>WishlistPage.razor</c>,
/// rows link to detail pages) and the anonymous shared view (<c>SharedWishlistPage.razor</c>, which
/// ignores <see cref="Href"/> - a recipient has no account to open a detail page with).
/// </summary>
public sealed record WishlistRow(string Href, string? ImageUrl, string? Shape, string? Title, int? Year, string? Subtitle = null)
{
    public static List<WishlistRow> FromMovies(List<MovieDto> movies) =>
        movies.ConvertAll(x => new WishlistRow($"/movies/{x.Id}", x.ImageUrl, null, x.Title, x.Year));

    public static List<WishlistRow> FromTvShows(List<TvShowDto> tvShows) =>
        tvShows.ConvertAll(x => new WishlistRow($"/tv-shows/{x.Id}", x.ImageUrl, null, x.Title, x.Year));

    public static List<WishlistRow> FromBooks(List<BookDto> books) =>
        books.ConvertAll(x => new WishlistRow($"/books/{x.Id}", x.ImageUrl, null, x.Title, x.Year, x.Author));

    public static List<WishlistRow> FromVideoGames(List<VideoGameDto> videoGames) =>
        videoGames.ConvertAll(x => new WishlistRow($"/video-games/{x.Id}", x.ImageUrl, "wide", x.Title, x.Year));
}
