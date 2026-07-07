using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Shared movie metadata (synopsis) - read-only, fetched separately from <see cref="MovieDto"/> since
/// it isn't the tenant's own data.
/// </summary>
public class MovieReferenceDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public List<string> Genres { get; set; } = [];

    public List<CastMemberDto> Cast { get; set; } = [];

    public string? ImageUrl { get; set; }
}
