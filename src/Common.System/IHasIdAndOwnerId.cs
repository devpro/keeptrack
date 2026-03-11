namespace Keeptrack.Common.System;

public interface IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public string OwnerId { get; set; }
}
