using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): <see cref="Domain.Services.GenericImportService"/> is pure and knows
/// nothing about the web contract, so <see cref="Controllers.GenericImportController"/> maps its rows here -
/// same shape as <see cref="AmazonOrderPreviewRowDtoMapper"/>. <see cref="EnumMappingStrategy.ByName"/> maps
/// the Domain <c>ImportMediaType</c> onto the identically-named Contracts one (drift between the two members
/// is then a build error, not a silent runtime mismatch).
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class GenericImportPreviewRowDtoMapper
{
    public partial Keeptrack.WebApi.Contracts.Dto.GenericImportPreviewRowDto ToDto(GenericImportPreviewRow model);
}
