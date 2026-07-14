using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Result of importing the personal "Voitures.xlsx" spreadsheet (fuel/maintenance history per car).
/// </summary>
public class CarHistoryImportResultDto
{
    public int CarsCreated { get; set; }

    public int CarsSkipped { get; set; }

    public int HistoryEntriesCreated { get; set; }

    /// <summary>
    /// Rows that couldn't be parsed (e.g. an unreadable date) and were skipped rather than guessed at.
    /// </summary>
    public List<string> Warnings { get; set; } = [];
}
