using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Shared book metadata (synopsis, cover) - read-only, fetched separately from <see cref="BookDto"/> since
/// it isn't the tenant's own data.
/// </summary>
public class BookReferenceDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? AuthorName { get; set; }

    public string? AuthorImageUrl { get; set; }

    public List<string> Genres { get; set; } = [];

    public string? ImageUrl { get; set; }
}
