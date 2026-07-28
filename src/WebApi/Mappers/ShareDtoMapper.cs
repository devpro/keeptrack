using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Maps the <see cref="ShareModel"/> grant to/from its public DTOs. The two <c>ShareCategory</c> enums
/// (Domain vs Contracts) are mapped by name, so a member drifting between them is a build error.
/// <see cref="Controllers.ShareController"/> owns setting <c>OwnerId</c>/<c>OwnerDisplayName</c> from the
/// authenticated caller after <see cref="ToModel"/>, never trusting them from the request body.
/// </summary>
[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class ShareDtoMapper
{
    // OwnerId is required non-nullable on the model, so it's given a placeholder here (overwritten
    // server-side from the caller's claims) rather than ignored - same pattern as the CRUD DTO mappers.
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
