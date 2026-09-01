using System.ComponentModel.DataAnnotations;

namespace Keeptrack.Common.System;

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
    /// <remarks>
    /// Validated here rather than left to whatever exception the repository happens to throw for an
    /// out-of-range value: a negative <c>Page</c> produces a negative Mongo <c>Skip</c>, which the driver
    /// rejects with an <see cref="System.ArgumentOutOfRangeException"/> that
    /// <c>ApiExceptionFilterAttribute</c> happens to map to 400 because it derives from
    /// <see cref="System.ArgumentException"/> - correct by accident, and its message is the driver's
    /// internal one rather than a real validation error. <c>[ApiController]</c> runs this attribute on
    /// model binding and answers 400 before the request ever reaches a repository.
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int Page { get; set; } = 1;

    /// <summary>
    /// Number of elements to return per page.
    /// </summary>
    /// <remarks>
    /// Deliberately has no upper bound, even though a very large value pulls an unbounded number of
    /// documents into memory in one request.
    /// A first pass here capped it at 100 and broke real production traffic: <c>CarDetail</c>,
    /// <c>HealthProfileDetail</c> and <c>HouseDetail</c> read a child collection with <c>pageSize=int.MaxValue</c>
    /// to fetch every one of a single parent's history rows in one page (see AGENTS.md's "Child entities"
    /// section, a child collection is expected to be bounded by one real parent's data), and
    /// <c>TvShowDetail</c>/<c>AlbumDetail</c>/<c>PlaylistDetail</c> use 5000 for the same reason.
    /// Only <c>Page</c> is validated for now; a real cap needs a second, purpose-built "fetch everything for
    /// this parent" shape rather than reusing the browse-list endpoint's own <c>pageSize</c>, which is a
    /// larger change than this fix.
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int PageSize { get; set; } = 20;

    /// <summary>
    /// Sort key (see <see cref="ListSort"/>: "title", "rating"). Null or empty means the default order,
    /// newest first. An unsupported key for the requested collection also falls back to the default.
    /// </summary>
    public string? Sort { get; set; }

    /// <summary>
    /// Elements to skip.
    /// </summary>
    public int Skip => (Page - 1) * PageSize;
}
