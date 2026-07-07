namespace Keeptrack.Domain.Models;

/// <summary>
/// A user's own general watch state for a show - distinct from per-episode watched dates. Nullable on
/// <see cref="TvShowModel.State"/>: unset means "no state chosen yet", not a default of any one value.
/// The enum type itself keeps the "Status" name (only <see cref="TvShowModel.State"/>'s property name was
/// renamed for parity with <see cref="VideoGameModel.State"/> - VideoGame's State is a plain string with no
/// equivalent enum to rename).
/// </summary>
public enum TvShowStatus
{
    Current,
    Finished,
    Stopped
}
