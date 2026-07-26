using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing a selected set of generic video game transaction rows.
/// </summary>
public class GenericVideoGameImportCommitResultDto
{
    /// <summary>Brand new video games created.</summary>
    public int VideoGamesCreated { get; set; }

    /// <summary>Existing video games (including ones created earlier in this same commit) that received an additional platform entry.</summary>
    public int VideoGamesMergedInto { get; set; }

    /// <summary>Rows whose transaction reference already matched an existing platform entry - not duplicated.</summary>
    public int VideoGamesSkipped { get; set; }

    /// <summary>
    /// The true per-row count of rows that got a platform entry added, whether the row's own new video game
    /// or an existing/already-created-this-batch one. <see cref="VideoGamesCreated"/>/<see cref="VideoGamesMergedInto"/>
    /// count distinct video games, not rows - several selected rows sharing a title can consolidate into
    /// one created video game, which makes those two counts add up to less than the number of rows selected
    /// even though nothing was lost. <c>RowsImported + VideoGamesSkipped</c> always equals the number of
    /// rows submitted - the reconciling total to show the user so they can trust nothing was silently dropped.
    /// </summary>
    public int RowsImported { get; set; }

    /// <summary>The title of each row counted in <see cref="VideoGamesSkipped"/>, so the user can see exactly
    /// which selected rows were treated as already-imported duplicates.</summary>
    public List<string> SkippedRowTitles { get; set; } = [];
}
