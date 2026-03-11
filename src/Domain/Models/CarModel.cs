using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class CarModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Name { get; set; }
}
