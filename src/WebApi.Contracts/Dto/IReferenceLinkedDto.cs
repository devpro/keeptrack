namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A DTO whose item can link to a shared reference document (movie, TV show, book, video game, album).
/// <see cref="ImageUrl"/> is read-only, hydrated server side from the linked reference on list reads and never accepted from the client.
/// </summary>
public interface IReferenceLinkedDto
{
    /// <summary>
    /// Id of the linked reference document, null or empty when unresolved.
    /// </summary>
    string? ReferenceId { get; }

    /// <summary>
    /// Cover image URL from the linked reference, hydrated server side on list reads.
    /// </summary>
    string? ImageUrl { get; set; }
}
