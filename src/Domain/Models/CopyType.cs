namespace Keeptrack.Domain.Models;

/// <summary>
/// Whether an owned copy is physical or digital, for every <see cref="OwnedVersionModel"/> and every <see cref="VideoGamePlatformModel"/>.
/// Physical is first so it is the default.
/// </summary>
public enum CopyType
{
    Physical,
    Digital
}
