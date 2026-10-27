using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only, for <see cref="Controllers.CarController.GetMetrics"/>.
/// <c>ByName</c> maps <see cref="CarLastRecordModel.EventType"/> onto the Contracts copy of its enum.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class CarMetricsDtoMapper
{
    public partial CarMetricsDto ToDto(CarMetricsModel model);
}
