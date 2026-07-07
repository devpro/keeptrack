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
}
