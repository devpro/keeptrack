using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only, for <see cref="Controllers.GenericVideoGameImportController"/>, like <see cref="AmazonOrderPreviewRowDtoMapper"/>.
/// </summary>
[Mapper]
public partial class GenericVideoGameImportPreviewRowDtoMapper
{
    public partial GenericVideoGameImportPreviewRowDto ToDto(GenericVideoGameImportPreviewRow model);
}
