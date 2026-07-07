namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Summary of a reference-data sync pass (periodic or admin-triggered "sync now").
/// </summary>
public class ReferenceSyncResultDto
{
    /// <summary>
    /// How many TV show reference documents were examined.
    /// </summary>
    public int TvShowsChecked { get; set; }

    /// <summary>
    /// How many of the examined TV show references had actual TMDB changes and were re-fetched.
    /// </summary>
    public int TvShowsUpdated { get; set; }

    /// <summary>
    /// How many movie reference documents were examined.
    /// </summary>
    public int MoviesChecked { get; set; }

    /// <summary>
    /// How many of the examined movie references had actual TMDB changes and were re-fetched.
    /// </summary>
    public int MoviesUpdated { get; set; }

    public int BooksChecked { get; set; }

    /// <summary>
    /// Open Library exposes no per-id "changed since" endpoint (unlike TMDB), so every examined book
    /// reference is always fully re-fetched - this count is always equal to <see cref="BooksChecked"/>.
    /// </summary>
    public int BooksUpdated { get; set; }

    public int VideoGamesChecked { get; set; }

    /// <summary>
    /// RAWG exposes no per-id "changed since" endpoint (unlike TMDB), so every examined game reference is
    /// always fully re-fetched - this count is always equal to <see cref="VideoGamesChecked"/>.
    /// </summary>
    public int VideoGamesUpdated { get; set; }

    public int AlbumsChecked { get; set; }

    /// <summary>
    /// Discogs exposes no per-id "changed since" endpoint (unlike TMDB), so every examined album reference
    /// is always fully re-fetched - this count is always equal to <see cref="AlbumsChecked"/>.
    /// </summary>
    public int AlbumsUpdated { get; set; }
}
