using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Result of importing the personal "Voitures.xlsx" spreadsheet, the fuel and maintenance history per car.
/// </summary>
public class CarHistoryImportResultDto
{
    public int CarsCreated { get; set; }

    public int CarsSkipped { get; set; }

    public int HistoryEntriesCreated { get; set; }

    /// <summary>
    /// Rows that could not be parsed, such as an unreadable date, skipped rather than guessed.
    /// </summary>
    public List<string> Warnings { get; set; } = [];
}
