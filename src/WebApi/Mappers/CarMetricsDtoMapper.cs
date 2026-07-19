using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto):
/// <see cref="Domain.Services.CarMetricsService"/> is a pure Domain-level computation with no Dto dependency,
/// so <see cref="Controllers.CarController.GetMetrics"/> maps its result here.
/// <c>ByName</c> is required because <see cref="CarLastRecordModel.EventType"/> maps to a differently-typed Contracts-side duplicate enum of the same name.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class CarMetricsDtoMapper
{
    public partial CarMetricsDto ToDto(CarMetricsModel model);
}
