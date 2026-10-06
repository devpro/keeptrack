namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing selected Amazon order rows, per trackable type, only the types present in the request being non-zero.
/// </summary>
public class AmazonImportCommitResultDto
{
    /// <summary>Brand new books created.</summary>
    public int BooksCreated { get; set; }

    /// <summary>Existing books, or ones created earlier in this commit, that received another owned version.</summary>
    public int BooksMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version, so they are not duplicated.</summary>
    public int BooksSkipped { get; set; }

    /// <summary>Brand new movies created.</summary>
    public int MoviesCreated { get; set; }

    /// <summary>Existing movies, or ones created earlier in this commit, that received another owned version.</summary>
    public int MoviesMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version, so they are not duplicated.</summary>
    public int MoviesSkipped { get; set; }

    /// <summary>Brand new TV shows created.</summary>
    public int TvShowsCreated { get; set; }

    /// <summary>Existing TV shows, or ones created earlier in this commit, that received another owned version.</summary>
    public int TvShowsMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version, so they are not duplicated.</summary>
    public int TvShowsSkipped { get; set; }

    /// <summary>Brand new video games created.</summary>
    public int VideoGamesCreated { get; set; }

    /// <summary>Existing video games, or ones created earlier in this commit, that received another platform entry.</summary>
    public int VideoGamesMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing platform entry, so they are not duplicated.</summary>
    public int VideoGamesSkipped { get; set; }

    /// <summary>Brand new gear items created.</summary>
    public int GearCreated { get; set; }

    /// <summary>Existing gear items, or ones created earlier in this commit, that received another owned version.</summary>
    public int GearMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version, so they are not duplicated.</summary>
    public int GearSkipped { get; set; }

    /// <summary>Brand new collectibles created.</summary>
    public int CollectiblesCreated { get; set; }

    /// <summary>Existing collectibles, or ones created earlier in this commit, that received another owned version.</summary>
    public int CollectiblesMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version, so they are not duplicated.</summary>
    public int CollectiblesSkipped { get; set; }
}
