using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Result of importing the personal "Journal_sante.xlsx" spreadsheet (one health journal, every family
/// member mixed in one sheet).
/// </summary>
public class HealthImportResultDto
{
    /// <summary>How many health profiles the "Personne" column created.</summary>
    public int ProfilesCreated { get; set; }

    /// <summary>How many "Personne" values matched an already-existing profile instead.</summary>
    public int ProfilesSkipped { get; set; }

    /// <summary>How many journal entries were created.</summary>
    public int RecordsCreated { get; set; }

    /// <summary>
    /// Rows that couldn't be parsed (an unreadable date, no person) and were skipped rather than guessed at.
    /// </summary>
    public List<string> Warnings { get; set; } = [];
}
