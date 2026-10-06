using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Wishlist;

/// <summary>
/// The projection all four wishlisted item types share, so one row loop replaces four near-identical markup blocks.
/// The owner's tabbed page (<c>WishlistPage.razor</c>) links rows to detail pages, and the anonymous shared view (<c>SharedWishlistPage.razor</c>) ignores <see cref="Href"/>, since a recipient has no account to open one with.
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

    public static List<WishlistRow> FromAlbums(List<AlbumDto> albums) =>
        albums.ConvertAll(x => new WishlistRow($"/albums/{x.Id}", x.ImageUrl, "square", x.Title, x.Year, x.Artist));
}
