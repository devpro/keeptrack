using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Maps the <see cref="ShareModel"/> grant to and from its public DTOs.
/// The Domain and Contracts <c>ShareCategory</c> enums map by name, so drift is a build error.
/// <see cref="Controllers.ShareController"/> sets <c>OwnerId</c> and <c>OwnerDisplayName</c> from the authenticated caller after <see cref="ToModel"/>, never from the request body.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class ShareDtoMapper
{
    // OwnerId is required, so it gets a placeholder the controller overwrites from the caller's claims, as in the CRUD DTO mappers
    [MapValue(nameof(ShareModel.OwnerId), "")]
    [MapperIgnoreTarget(nameof(ShareModel.Id))]
    [MapperIgnoreTarget(nameof(ShareModel.OwnerDisplayName))]
    [MapperIgnoreTarget(nameof(ShareModel.CreatedAt))]
    public partial ShareModel ToModel(CreateShareRequestDto dto);

    [MapperIgnoreSource(nameof(ShareModel.OwnerId))]
    [MapperIgnoreSource(nameof(ShareModel.OwnerDisplayName))]
    public partial ShareDto ToDto(ShareModel model);

    [MapProperty(nameof(ShareModel.Id), nameof(SharedCollectionSummaryDto.ShareId))]
    [MapperIgnoreSource(nameof(ShareModel.OwnerId))]
    [MapperIgnoreSource(nameof(ShareModel.RecipientEmail))]
    [MapperIgnoreSource(nameof(ShareModel.Label))]
    [MapperIgnoreSource(nameof(ShareModel.CreatedAt))]
    public partial SharedCollectionSummaryDto ToSummaryDto(ShareModel model);
}
