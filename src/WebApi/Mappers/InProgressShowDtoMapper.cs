using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only, for <see cref="Controllers.WatchNextController"/>, injected directly.
/// </summary>
[Mapper]
public partial class InProgressShowDtoMapper
{
    // WatchNextController sets ImageUrl from the reference documents it already fetched
    [MapperIgnoreTarget(nameof(InProgressShowDto.ImageUrl))]
    public partial InProgressShowDto ToDto(InProgressShowModel model);
}
