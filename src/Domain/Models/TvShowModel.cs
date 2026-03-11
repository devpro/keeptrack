using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class TvShowModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }
}
