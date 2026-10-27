namespace Keeptrack.Domain.Models;

/// <summary>
/// The user's overall watch state for a show, distinct from per-episode watched dates.
/// Nullable on <see cref="TvShowModel.State"/>, where unset means no state chosen yet rather than a default.
/// </summary>
public enum TvShowStatus
{
    Current,
    Finished,
    Stopped
}
