using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only, for <see cref="Controllers.HouseController.GetMetrics"/>.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HouseMetricsDtoMapper
{
    public partial HouseMetricsDto ToDto(HouseMetricsModel model);
}
