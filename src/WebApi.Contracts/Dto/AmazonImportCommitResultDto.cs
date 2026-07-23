namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing a selected set of Amazon order rows, broken down per trackable item type - only
/// the types actually present in the commit request end up non-zero.
/// </summary>
public class AmazonImportCommitResultDto
{
    /// <summary>Brand new books created.</summary>
    public int BooksCreated { get; set; }

    /// <summary>Existing books (including ones created earlier in this same commit) that received an additional owned version.</summary>
    public int BooksMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version - not duplicated.</summary>
    public int BooksSkipped { get; set; }

    /// <summary>Brand new movies created.</summary>
    public int MoviesCreated { get; set; }

    /// <summary>Existing movies (including ones created earlier in this same commit) that received an additional owned version.</summary>
    public int MoviesMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version - not duplicated.</summary>
    public int MoviesSkipped { get; set; }

    /// <summary>Brand new TV shows created.</summary>
    public int TvShowsCreated { get; set; }

    /// <summary>Existing TV shows (including ones created earlier in this same commit) that received an additional owned version.</summary>
    public int TvShowsMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version - not duplicated.</summary>
    public int TvShowsSkipped { get; set; }

    /// <summary>Brand new video games created.</summary>
    public int VideoGamesCreated { get; set; }

    /// <summary>Existing video games (including ones created earlier in this same commit) that received an additional platform entry.</summary>
    public int VideoGamesMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing platform entry - not duplicated.</summary>
    public int VideoGamesSkipped { get; set; }

    /// <summary>Brand new gear items created.</summary>
    public int GearCreated { get; set; }

    /// <summary>Existing gear items (including ones created earlier in this same commit) that received an additional owned version.</summary>
    public int GearMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version - not duplicated.</summary>
    public int GearSkipped { get; set; }

    /// <summary>Brand new collectibles created.</summary>
    public int CollectiblesCreated { get; set; }

    /// <summary>Existing collectibles (including ones created earlier in this same commit) that received an additional owned version.</summary>
    public int CollectiblesMergedInto { get; set; }

    /// <summary>Rows whose order reference already matched an existing owned version - not duplicated.</summary>
    public int CollectiblesSkipped { get; set; }
}
