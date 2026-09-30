namespace Keeptrack.Domain.Models;

/// <summary>
/// The tenant records a reference link is written to.
/// Creating an item, checking it for a match and adding it from Explore link that one item and never another record, since another owner's copy is theirs to check.
/// Only an admin's link reaches other records: every unlinked one matching exactly what the admin linked with.
/// </summary>
public sealed record ReferenceLinkTarget
{
    public string? ItemId { get; private init; }

    public string? OwnerId { get; private init; }

    public string? Title { get; private init; }

    public int? Year { get; private init; }

    /// <summary>The artist an admin linked an album with, required there since it is half an album's identity.</summary>
    public string? Creator { get; private init; }

    public static ReferenceLinkTarget Item(string itemId, string ownerId) => new() { ItemId = itemId, OwnerId = ownerId };

    public static ReferenceLinkTarget Matching(string title, int? year, string? creator = null) => new() { Title = title, Year = year, Creator = creator };
}
