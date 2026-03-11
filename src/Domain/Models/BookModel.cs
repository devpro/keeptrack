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

    public DateOnly? FinishedAt { get; set; }
}
