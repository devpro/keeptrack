namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The caller's own opt-in/opt-out feature toggles. Always "mine" - never referenced by id, never listed.
/// </summary>
public class UserPreferencesDto
{
    /// <summary>
    /// Shows an "open in a new tab" link to chasse-aux-livres.fr next to a book's ISBN field.
    /// </summary>
    public bool ShowChasseAuxLivresLink { get; set; }
}
