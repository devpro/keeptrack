using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.HealthMetricsService"/> is a pure
/// Domain-level computation with no Dto dependency, so <see cref="Controllers.HealthProfileController.GetMetrics"/>
/// maps its result here - same shape as <see cref="HouseMetricsDtoMapper"/>.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HealthMetricsDtoMapper
{
    public partial HealthMetricsDto ToDto(HealthMetricsModel model);
}
