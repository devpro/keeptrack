namespace KeepTrack.Common.System;

/// <summary>
/// Data query object.
/// </summary>
/// <remarks>
/// See https://learn.microsoft.com/en-us/azure/architecture/patterns/cqrs
/// </remarks>
public class PagedRequest
{
    /// <summary>
    /// Search text.
    /// </summary>
    public string? Search { get; set; }
    
    /// <summary>
    /// Page number to return (starts with 1).
    /// </summary>
    public int Page { get; set; } = 1;

    /// <summary>
    /// Number of elements to return per page.
    /// </summary>
    public int PageSize { get; set; } = 20;

    /// <summary>
    /// Elements to skip.
    /// </summary>
    public int Skip => (Page - 1) * PageSize;
}
