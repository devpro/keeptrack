using System.ComponentModel.DataAnnotations;

namespace Keeptrack.Common.System;

public class PagedRequest
{
    /// <summary>
    /// Search text.
    /// </summary>
    public string? Search { get; set; }

    /// <summary>
    /// Page number to return (starts with 1).
    /// </summary>
    /// <remarks>
    /// Validated on model binding, so <c>[ApiController]</c> answers 400 before the request reaches a repository.
    /// A negative page would otherwise become a negative MongoDB <c>Skip</c>, rejected with the driver's internal message rather than a validation error.
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int Page { get; set; } = 1;

    /// <summary>
    /// Number of elements to return per page.
    /// </summary>
    /// <remarks>
    /// Deliberately unbounded, although a very large value loads that many documents in one request.
    /// Detail pages fetch all of a parent's children in one page: <c>CarDetail</c>, <c>HealthProfileDetail</c> and <c>HouseDetail</c> ask for <c>int.MaxValue</c>,
    /// and <c>TvShowDetail</c>, <c>AlbumDetail</c> and <c>PlaylistDetail</c> for 5000.
    /// A cap needs a dedicated "all children of this parent" endpoint first (see docs/backlog.md).
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int PageSize { get; set; } = 20;

    /// <summary>
    /// Sort key (see <see cref="ListSort"/>: "title", "rating").
    /// Null or empty means the default order, newest first.
    /// An unsupported key for the requested collection also falls back to the default.
    /// </summary>
    public string? Sort { get; set; }

    public int Skip => (Page - 1) * PageSize;
}
