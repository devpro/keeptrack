namespace Keeptrack.Domain.Models;

/// <summary>
/// One selected or edited import row in Domain shape, which <see cref="Services.OwnedItemImportCommitCoordinator"/> creates or merges as the type <see cref="MediaType"/> names.
/// Every owned-item importer (Amazon, generic) shares it, so the create and merge orchestration exists once.
/// The importers differ only in how they build <see cref="OwnedVersion"/>'s reference text and <see cref="ProvenanceNotes"/>, computed before handing the input over.
/// </summary>
public sealed class OwnedItemImportInput
{
    public required ImportMediaType MediaType { get; init; }

    /// <summary>The title to create or match the item under, possibly edited by the user.</summary>
    public required string Title { get; init; }

    /// <summary>Notes recording the source's original listing text, written onto a new item only, never an existing one.</summary>
    public required string ProvenanceNotes { get; init; }

    public int? Year { get; init; }

    /// <summary>Books only: the created book's author.</summary>
    public string? Author { get; init; }

    /// <summary>Books only: the created book's ISBN.</summary>
    public string? Isbn { get; init; }

    /// <summary>
    /// Video games only: the platform of the created game's copy.
    /// Required when <see cref="MediaType"/> is <see cref="ImportMediaType.VideoGame"/>, which the caller validates.
    /// </summary>
    public string? Platform { get; init; }

    /// <summary>
    /// The owned copy to attach.
    /// It is added to the item's <c>OwnedVersions</c> as is, except for a video game, where its fields seed a <see cref="VideoGamePlatformModel"/> with <see cref="Platform"/>.
    /// </summary>
    public required OwnedVersionModel OwnedVersion { get; init; }
}
