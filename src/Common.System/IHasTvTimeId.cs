namespace Keeptrack.Common.System;

/// <summary>
/// A record that can carry the stable id of the TV Time item it was imported from. Lets the import
/// pipeline match and de-duplicate shows and movies by this immutable id generically, independent of
/// their (reference-enrichment-mutable) title.
/// </summary>
public interface IHasTvTimeId
{
    public string? TvTimeId { get; set; }
}
