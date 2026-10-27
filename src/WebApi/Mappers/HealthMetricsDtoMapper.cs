using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only, for <see cref="Controllers.HealthProfileController.GetMetrics"/>, like <see cref="HouseMetricsDtoMapper"/>.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HealthMetricsDtoMapper
{
    public partial HealthMetricsDto ToDto(HealthMetricsModel model);
}
