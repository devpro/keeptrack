namespace Keeptrack.Domain.Models;

/// <summary>
/// A tenant item that carries a link to a shared reference document, plus the rating denormalized from it.
/// </summary>
/// <remarks>
/// <para>
/// These four fields are <b>server-owned</b>.
/// They are written only by reference resolution, by the detail page's "check for reference match", and by an admin unlink - each straight through a repository - and never from a client's own payload.
/// An update is a full replace of the document, so without this a client that merely echoes the fields back decides them, and one holding a copy fetched before the item was linked silently erases the link by saving anything at all.
/// </para>
/// <para>
/// Declared here rather than per controller because the rule is the same for all five reference-linked types, and the fields are named identically on every one of them - the same reason <c>IHasReferenceRating</c> exists on the entity side.
/// </para>
/// </remarks>
public interface IReferenceLinkedModel
{
    string? ReferenceId { get; set; }

    double? ReferenceRating { get; set; }

    double? ReferenceRatingScale { get; set; }

    string? ReferenceRatingSource { get; set; }
}
