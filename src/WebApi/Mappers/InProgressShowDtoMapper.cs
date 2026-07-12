using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.WatchNextService"/> is a pure Domain-level
/// computation with no Dto dependency, so <see cref="Controllers.WatchNextController"/> maps its result
/// here. Injected directly, same shape as the reference-data storage mappers - see
/// <c>docs/automapper-removal-plan.md</c>.
/// </summary>
[Mapper]
public partial class InProgressShowDtoMapper
{
    public partial InProgressShowDto ToDto(InProgressShowModel model);
}
