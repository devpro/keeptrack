using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One document per user (see <see cref="Repositories.IUserPreferencesRepository"/>). The opt-in/opt-out
/// toggles themselves live under <see cref="Features"/>, not as flat properties here, so a new one only
/// ever means adding a property to <see cref="UserPreferencesFeaturesModel"/>.
/// </summary>
public class UserPreferencesModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public UserPreferencesFeaturesModel Features { get; set; } = new();
}
