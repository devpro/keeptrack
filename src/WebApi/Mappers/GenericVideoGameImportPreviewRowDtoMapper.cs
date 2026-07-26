using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.GenericVideoGameImportService"/> is pure and
/// knows nothing about the web contract, so <see cref="Controllers.GenericVideoGameImportController"/> maps
/// its rows here - same shape as <see cref="AmazonOrderPreviewRowDtoMapper"/>.
/// </summary>
[Mapper]
public partial class GenericVideoGameImportPreviewRowDtoMapper
{
    public partial GenericVideoGameImportPreviewRowDto ToDto(GenericVideoGameImportPreviewRow model);
}
