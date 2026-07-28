using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing a selected set of generic-import rows, broken down per trackable item type - only the
/// types actually present in the commit request end up non-zero - plus the reconciling per-row totals.
/// </summary>
public class GenericImportCommitResultDto
{
    public int BooksCreated { get; set; }
    public int BooksMergedInto { get; set; }
    public int BooksSkipped { get; set; }

    public int MoviesCreated { get; set; }
    public int MoviesMergedInto { get; set; }
    public int MoviesSkipped { get; set; }

    public int TvShowsCreated { get; set; }
    public int TvShowsMergedInto { get; set; }
    public int TvShowsSkipped { get; set; }

    public int VideoGamesCreated { get; set; }
    public int VideoGamesMergedInto { get; set; }
    public int VideoGamesSkipped { get; set; }

    public int GearCreated { get; set; }
    public int GearMergedInto { get; set; }
    public int GearSkipped { get; set; }

    public int CollectiblesCreated { get; set; }
    public int CollectiblesMergedInto { get; set; }
    public int CollectiblesSkipped { get; set; }

    /// <summary>
    /// The true per-row count of rows that got an owned copy added, whether onto a brand-new item or an
    /// existing/already-created-this-batch one. The per-type Created/MergedInto counts are per distinct item,
    /// so rows sharing a title consolidate and make them add up to less than the selected-row count without any
    /// loss. <c>RowsImported</c> + the sum of every type's <c>*Skipped</c> always equals the number of rows
    /// submitted - the reconciling total to show the user so they can trust nothing was silently dropped.
    /// </summary>
    public int RowsImported { get; set; }

    /// <summary>The title of each row skipped as an already-imported duplicate, so the user can see exactly which.</summary>
    public List<string> SkippedRowTitles { get; set; } = [];
}
