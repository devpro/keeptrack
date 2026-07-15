namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A DTO whose item type can be linked to a shared reference document (movie, TV show, book, video game,
/// album). <see cref="ImageUrl"/> is read-only presentation data hydrated server-side from the linked
/// reference on list reads - it is never accepted from client input.
/// </summary>
public interface IReferenceLinkedDto
{
    /// <summary>
    /// Id of the linked shared reference document, empty/null when unresolved.
    /// </summary>
    string? ReferenceId { get; }

    /// <summary>
    /// Cover/poster image URL from the linked reference document, hydrated server-side on list reads.
    /// </summary>
    string? ImageUrl { get; set; }
}
