using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing selected generic import rows, per trackable type, only the types present in the request being non-zero, plus per-row totals.
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
    /// The rows that got an owned copy added, on a new item or an existing one.
    /// The per-type created and merged counts are per distinct item, so rows sharing a title make them add up to less than the rows, without any loss.
    /// <c>RowsImported</c> plus every type's <c>*Skipped</c> always equals the rows submitted, which shows the user nothing was silently dropped.
    /// </summary>
    public int RowsImported { get; set; }

    /// <summary>The title of each row skipped as a duplicate of an earlier import.</summary>
    public List<string> SkippedRowTitles { get; set; } = [];
}
