using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One document per user (see <see cref="Repositories.IUserPreferencesRepository"/>).
/// The toggles live under <see cref="Features"/> rather than here, so a new one is only a property on <see cref="UserPreferencesFeaturesModel"/>.
/// </summary>
public class UserPreferencesModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public UserPreferencesFeaturesModel Features { get; set; } = new();
}
