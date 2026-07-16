namespace Keeptrack.Domain.Models;

/// <summary>
/// Whether an owned copy of a tracked item is physical or digital - used by every
/// <see cref="OwnedVersionModel"/> and by <see cref="VideoGamePlatformModel"/>'s per-platform copies.
/// Physical is deliberately first so it's the default.
/// </summary>
public enum CopyType
{
    Physical,
    Digital
}
