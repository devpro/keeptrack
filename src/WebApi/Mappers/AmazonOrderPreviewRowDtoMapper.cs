using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.AmazonOrderPreviewService"/> is pure and
/// knows nothing about the web contract, so <see cref="Controllers.AmazonImportController"/> maps its rows
/// here - same shape as <see cref="InProgressShowDtoMapper"/>.
/// </summary>
[Mapper]
public partial class AmazonOrderPreviewRowDtoMapper
{
    public partial AmazonOrderPreviewRowDto ToDto(AmazonOrderPreviewRow model);
}
