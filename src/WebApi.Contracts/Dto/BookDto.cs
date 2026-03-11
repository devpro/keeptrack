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
    /// Book finished reading date.
    /// </summary>
    public DateOnly? FinishedAt { get; set; }
}
