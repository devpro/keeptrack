using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class BookModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Author { get; set; }

    public string? Series { get; set; }

    public float? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Notes { get; set; }

    public DateOnly? FirstReadAt { get; set; }
}
