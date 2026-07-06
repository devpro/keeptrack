namespace Keeptrack.Domain.Models;

/// <summary>
/// A user's own general watch status for a show - distinct from per-episode watched dates. Nullable on
/// <see cref="TvShowModel.Status"/>: unset means "no status chosen yet", not a default of any one value.
/// </summary>
public enum TvShowStatus
{
    Current,
    Finished,
    Stopped
}
