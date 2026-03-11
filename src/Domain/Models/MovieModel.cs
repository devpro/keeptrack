using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class MovieModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public int? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Notes { get; set; }

    public string? ImdbPageId { get; set; }

    public string? AllocineId { get; set; }
}
