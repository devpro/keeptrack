using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.HouseMetricsService"/> is a pure Domain-level
/// computation with no Dto dependency, so <see cref="Controllers.HouseController.GetMetrics"/> maps its
/// result here.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HouseMetricsDtoMapper
{
    public partial HouseMetricsDto ToDto(HouseMetricsModel model);
}
