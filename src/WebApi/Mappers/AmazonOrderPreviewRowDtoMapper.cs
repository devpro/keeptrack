using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only: <see cref="Domain.Services.AmazonOrderPreviewService"/> knows nothing of the web contract, so <see cref="Controllers.AmazonImportController"/> maps its rows here.
/// </summary>
[Mapper]
public partial class AmazonOrderPreviewRowDtoMapper
{
    public partial AmazonOrderPreviewRowDto ToDto(AmazonOrderPreviewRow model);
}
