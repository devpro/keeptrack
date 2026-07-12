using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.CarMetricsService"/> is a pure Domain-level
/// computation with no Dto dependency, so <see cref="Controllers.CarController.GetMetrics"/> maps its
/// result here. Mapperly preserves a null <see cref="CarMetricsModel.NextMaintenance"/> as null natively -
/// no <c>AllowNull()</c>-style opt-out needed, unlike the AutoMapper original.
/// </summary>
[Mapper]
public partial class CarMetricsDtoMapper
{
    public partial CarMetricsDto ToDto(CarMetricsModel model);
}
