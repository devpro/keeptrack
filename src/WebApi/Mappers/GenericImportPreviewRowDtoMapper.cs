using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only, for <see cref="Controllers.GenericImportController"/>, like <see cref="AmazonOrderPreviewRowDtoMapper"/>.
/// <see cref="EnumMappingStrategy.ByName"/> maps the Domain <c>ImportMediaType</c> onto its Contracts copy, so drift is a build error.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class GenericImportPreviewRowDtoMapper
{
    public partial Keeptrack.WebApi.Contracts.Dto.GenericImportPreviewRowDto ToDto(GenericImportPreviewRow model);
}
