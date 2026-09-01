namespace Keeptrack.Domain.Models;

/// <summary>
/// One user-selected/edited import row, already translated from the web contract into pure Domain shape, ready
/// for <see cref="Services.OwnedItemImportCommitCoordinator"/> to create/merge across whichever trackable type
/// <see cref="MediaType"/> names. Shared by every owned-item importer (Amazon, generic store/CSV) so the
/// six-type create/merge orchestration lives in exactly one place - the two importers differ only in how they
/// build <see cref="OwnedVersion"/>'s reference text and <see cref="ProvenanceNotes"/>, which they compute
/// themselves before handing the input over.
/// </summary>
public sealed class OwnedItemImportInput
{
    public required ImportMediaType MediaType { get; init; }

    /// <summary>The (possibly user-edited) title to create/match the item under.</summary>
    public required string Title { get; init; }

    /// <summary>Notes stamped onto a newly-created item (never onto a pre-existing one) recording the source's
    /// original listing text - see the importers' own <c>BuildProvenanceNotes</c>.</summary>
    public required string ProvenanceNotes { get; init; }

    public int? Year { get; init; }

    /// <summary>Book-only - the created book's author. Null (stored as empty) for every other type.</summary>
    public string? Author { get; init; }

    /// <summary>Book-only - the created book's ISBN.</summary>
    public string? Isbn { get; init; }

    /// <summary>VideoGame-only - the platform name for the created game's copy. Required when
    /// <see cref="MediaType"/> is <see cref="ImportMediaType.VideoGame"/> (validated by the caller).</summary>
    public string? Platform { get; init; }

    /// <summary>
    /// The owned copy to attach. For every non-video-game type this is added to the item's
    /// <c>OwnedVersions</c> as-is; for a video game its shared fields (copy type, price, vendor, acquired date,
    /// reference, product name) seed a <see cref="VideoGamePlatformModel"/> alongside <see cref="Platform"/>.
    /// </summary>
    public required OwnedVersionModel OwnedVersion { get; init; }
}
