using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Shared show metadata (synopsis, episode titles) - read-only, fetched separately from
/// <see cref="TvShowDto"/> since it isn't the tenant's own data.
/// </summary>
public class TvShowReferenceDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public List<ReferenceEpisodeDto> Episodes { get; set; } = [];
}
