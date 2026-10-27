namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Summary of a reference-data sync pass, periodic or an admin's "sync now".
/// </summary>
public class ReferenceSyncResultDto
{
    /// <summary>
    /// How many TV show reference documents were examined.
    /// </summary>
    public int TvShowsChecked { get; set; }

    /// <summary>
    /// How many of the examined TV show references had TMDB changes and were fetched again.
    /// </summary>
    public int TvShowsUpdated { get; set; }

    /// <summary>
    /// How many movie reference documents were examined.
    /// </summary>
    public int MoviesChecked { get; set; }

    /// <summary>
    /// How many of the examined movie references had TMDB changes and were fetched again.
    /// </summary>
    public int MoviesUpdated { get; set; }

    public int BooksChecked { get; set; }

    /// <summary>
    /// Always equal to <see cref="BooksChecked"/>, since no book provider has a "changed since" endpoint like TMDB's, so every examined reference is fetched again.
    /// </summary>
    public int BooksUpdated { get; set; }

    public int VideoGamesChecked { get; set; }

    /// <summary>
    /// Always equal to <see cref="VideoGamesChecked"/>, since no game provider has a "changed since" endpoint like TMDB's, so every examined reference is fetched again.
    /// </summary>
    public int VideoGamesUpdated { get; set; }

    public int AlbumsChecked { get; set; }

    /// <summary>
    /// Always equal to <see cref="AlbumsChecked"/>, since Discogs has no "changed since" endpoint like TMDB's, so every examined reference is fetched again.
    /// </summary>
    public int AlbumsUpdated { get; set; }

    /// <summary>
    /// How many finished TV shows were reopened as current, because their refreshed episode guide lists an aired episode after the last one watched.
    /// </summary>
    public int FinishedShowsReopened { get; set; }

    /// <summary>
    /// How many Explore rankings (a domain plus an ordering, such as video games by IGDB critic score) were rebuilt this pass.
    /// Zero when every ranking was within its longer staleness window, since references are checked far more often than rankings.
    /// </summary>
    public int ExploreRankingsRefreshed { get; set; }

    /// <summary>How many ranked Explore catalogue entries were written across those rankings.</summary>
    public int ExploreEntriesRefreshed { get; set; }

    /// <summary>
    /// How many Explore entries gained an IMDb rating this pass.
    /// Each costs a TMDB and an OMDb call within the shared daily budget, so it stays well under the entries until coverage catches up.
    /// Zero unless IMDb is a domain's selected rating source.
    /// </summary>
    public int ExploreImdbRatingsBackfilled { get; set; }
}
