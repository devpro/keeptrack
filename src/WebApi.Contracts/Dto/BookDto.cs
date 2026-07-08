using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Book data transfer object.
/// </summary>
public class BookDto : IHasId
{
    /// <summary>
    /// Book ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Book title.
    /// </summary>
    /// <example>The Hobbit</example>
    public string? Title { get; set; }

    /// <summary>
    /// Book author.
    /// </summary>
    /// <example>J.R.R. Tolkien</example>
    public string? Author { get; set; }

    /// <summary>
    /// Book series.
    /// </summary>
    /// <example>Middle-earth Universe</example>
    public string? Series { get; set; }

    /// <summary>
    /// Publication year.
    /// </summary>
    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Book finished reading date.
    /// </summary>
    public DateOnly? FirstReadAt { get; set; }

    /// <summary>
    /// Id of the linked <c>book_reference</c> document, when a match has been found.
    /// </summary>
    public string? ReferenceId { get; set; }

    public bool IsFavorite { get; set; }

    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }
}
