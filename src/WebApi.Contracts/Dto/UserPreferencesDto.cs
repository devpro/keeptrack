namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The caller's own preferences, never referenced by id nor listed.
/// </summary>
public class UserPreferencesDto
{
    /// <summary>
    /// The caller's opt-in toggles.
    /// </summary>
    public UserPreferencesFeaturesDto Features { get; set; } = new();
}
