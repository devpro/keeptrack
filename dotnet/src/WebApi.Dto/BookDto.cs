using System;

namespace KeepTrack.WebApi.Dto;

/// <summary>
/// Book data transfer object.
/// </summary>
public class BookDto
{
    /// <summary>
    /// Book ID.
    /// </summary>
    public string Id { get; set; }

    /// <summary>
    /// Book title.
    /// </summary>
    public string Title { get; set; }

    /// <summary>
    /// Book author.
    /// </summary>
    public string Author { get; set; }

    /// <summary>
    /// Book series.
    /// </summary>
    public string Series { get; set; }

    /// <summary>
    /// Book finished reading date.
    /// </summary>
    public DateTime? FinishedAt { get; set; }
}
