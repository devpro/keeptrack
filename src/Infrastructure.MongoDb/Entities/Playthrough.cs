using System;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Playthrough
{
    public required string Label { get; set; }

    public DateTime? CompletedAt { get; set; }
}
