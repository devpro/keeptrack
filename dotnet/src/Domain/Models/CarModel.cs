using KeepTrack.Common.System;

namespace KeepTrack.Domain.Models;

public class CarModel : IHasIdAndOwnerId
{
    public string Id { get; set; } = null!;

    public required string OwnerId { get; set; }

    public required string Name { get; set; }
}
