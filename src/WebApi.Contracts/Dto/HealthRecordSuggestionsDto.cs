using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The free-text values one account has already recorded in its health journal, offered back as
/// suggestions when adding an entry. Both lists travel together because the form needs both the moment it
/// opens - unlike gear categories or fuel grades, which are one field each and so are one endpoint each.
/// Always owner-scoped: a specialty or a practitioner's name is sensitive and is never shared across
/// accounts.
/// </summary>
public class HealthRecordSuggestionsDto
{
    /// <summary>
    /// Medical specialties already recorded ("généraliste", "dentiste", ...), sorted case-insensitively.
    /// </summary>
    public List<string> Specialties { get; set; } = [];

    /// <summary>
    /// Practitioner names already recorded, sorted case-insensitively.
    /// </summary>
    public List<string> Practitioners { get; set; } = [];
}
