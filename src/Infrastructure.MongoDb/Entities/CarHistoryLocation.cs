using System.Collections.Generic;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class CarHistoryLocation
{
    public required string City { get; set; }

    public List<double>? Coordinates { get; set; }
}
