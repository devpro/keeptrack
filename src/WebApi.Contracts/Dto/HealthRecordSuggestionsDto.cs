using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The free-text values one account already recorded in its health journal, offered as suggestions when adding an entry.
/// Both lists travel together, since the form needs both as it opens, where gear categories and fuel grades are one field and one endpoint each.
/// Always owner-scoped: a specialty or a practitioner's name is sensitive and never shared across accounts.
/// </summary>
public class HealthRecordSuggestionsDto
{
    /// <summary>
    /// Medical specialties already recorded ("généraliste", "dentiste"), sorted case-insensitively.
    /// </summary>
    public List<string> Specialties { get; set; } = [];

    /// <summary>
    /// Practitioner names already recorded, sorted case-insensitively.
    /// </summary>
    public List<string> Practitioners { get; set; } = [];
}
