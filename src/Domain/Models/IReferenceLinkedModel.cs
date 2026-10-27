namespace Keeptrack.Domain.Models;

/// <summary>
/// A tenant item that carries a link to a shared reference document, plus the rating denormalized from it.
/// </summary>
/// <remarks>
/// <para>
/// These four fields are <b>server-owned</b>.
/// Only reference resolution, the detail page's "check for reference match" and an admin unlink write them, each through a repository, never from a client's payload.
/// An update replaces the whole document, so a client holding a copy fetched before the item was linked would otherwise erase the link by saving anything.
/// </para>
/// <para>
/// Declared once rather than per controller, since the rule and the field names are the same on all five reference-linked types,
/// as <c>IHasReferenceRating</c> is on the entity side.
/// </para>
/// </remarks>
public interface IReferenceLinkedModel
{
    string? ReferenceId { get; set; }

    double? ReferenceRating { get; set; }

    double? ReferenceRatingScale { get; set; }

    string? ReferenceRatingSource { get; set; }
}
