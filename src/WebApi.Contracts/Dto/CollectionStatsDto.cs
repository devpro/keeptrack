namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// How many items the caller has in each collection - backs the Home page's "your collection" overview.
/// </summary>
public class CollectionStatsDto
{
    /// <summary>Number of books.</summary>
    public long Books { get; set; }

    /// <summary>Number of movies.</summary>
    public long Movies { get; set; }

    /// <summary>Number of TV shows.</summary>
    public long TvShows { get; set; }

    /// <summary>Number of episodes marked watched, across every show.</summary>
    public long EpisodesWatched { get; set; }

    /// <summary>Number of music albums.</summary>
    public long Albums { get; set; }

    /// <summary>Number of playlists.</summary>
    public long Playlists { get; set; }

    /// <summary>Number of video games.</summary>
    public long VideoGames { get; set; }

    /// <summary>Number of cars.</summary>
    public long Cars { get; set; }

    /// <summary>Number of houses.</summary>
    public long Houses { get; set; }

    /// <summary>Number of collectibles.</summary>
    public long Collectibles { get; set; }

    /// <summary>Number of gear items.</summary>
    public long Gear { get; set; }
}
