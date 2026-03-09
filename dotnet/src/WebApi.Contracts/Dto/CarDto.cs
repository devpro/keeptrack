using KeepTrack.Common.Collections.Generic;

namespace KeepTrack.WebApi.Contracts.Dto;

/// <summary>
/// Car data transfer object.
/// </summary>
public class CarDto: IHasId
{
    /// <summary>
    /// Car ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Car name.
    /// </summary>
    public string? Name { get; set; }
}
