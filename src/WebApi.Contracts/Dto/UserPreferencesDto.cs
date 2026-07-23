namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The caller's own preferences. Always "mine" - never referenced by id, never listed.
/// </summary>
public class UserPreferencesDto
{
    /// <summary>
    /// The caller's opt-in/opt-out feature toggles.
    /// </summary>
    public UserPreferencesFeaturesDto Features { get; set; } = new();
}
