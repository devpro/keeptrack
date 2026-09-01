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

    /// <summary>
    /// How many finished TV shows were reopened as "current" because their (freshly synced) reference episode
    /// guide now lists an aired episode beyond the last one watched - see the finished-show status
    /// reconciliation that runs right after the reference refresh.
    /// </summary>
    public int FinishedShowsReopened { get; set; }

    /// <summary>
    /// How many Explore discovery rankings (a domain plus an ordering, e.g. video games by Metacritic) were
    /// rebuilt this pass. Zero when every stored ranking was still within its own, much longer, staleness
    /// window - the reference documents above are re-checked far more often than the discovery lists.
    /// </summary>
    public int ExploreRankingsRefreshed { get; set; }

    /// <summary>How many ranked Explore catalogue entries were written across those rankings.</summary>
    public int ExploreEntriesRefreshed { get; set; }

    /// <summary>
    /// How many Explore catalogue entries gained an IMDb rating this pass. Bounded per pass (each costs a TMDB
    /// plus an OMDb call), so this is expected to be well under the number of entries until coverage catches
    /// up; it is zero unless IMDb is actually a domain's selected rating source.
    /// </summary>
    public int ExploreImdbRatingsBackfilled { get; set; }
}
