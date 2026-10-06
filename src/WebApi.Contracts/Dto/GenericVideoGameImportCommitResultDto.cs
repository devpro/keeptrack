using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing selected video game transaction rows.
/// </summary>
public class GenericVideoGameImportCommitResultDto
{
    public int VideoGamesCreated { get; set; }

    /// <summary>Existing video games, or ones created earlier in this commit, that received another platform entry.</summary>
    public int VideoGamesMergedInto { get; set; }

    /// <summary>Rows whose transaction reference already matched an existing platform entry, so they are not duplicated.</summary>
    public int VideoGamesSkipped { get; set; }

    /// <summary>
    /// The rows that got a platform entry added, on a new game or an existing one.
    /// <see cref="VideoGamesCreated"/> and <see cref="VideoGamesMergedInto"/> count distinct games, so rows sharing a title make them add up to less than the rows, without any loss.
    /// <c>RowsImported + VideoGamesSkipped</c> always equals the rows submitted, which shows the user nothing was silently dropped.
    /// </summary>
    public int RowsImported { get; set; }

    /// <summary>The title of each row counted in <see cref="VideoGamesSkipped"/>, so the user sees which rows were duplicates.</summary>
    public List<string> SkippedRowTitles { get; set; } = [];
}
