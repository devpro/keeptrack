namespace Keeptrack.Common.System;

/// <summary>
/// A record that can carry the stable id of the TV Time item it was imported from.
/// A re-import matches shows and movies by this id rather than by title, since reference resolution rewrites the title.
/// </summary>
public interface IHasTvTimeId
{
    public string? TvTimeId { get; set; }
}
