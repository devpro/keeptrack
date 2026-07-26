using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Unlike every other <see cref="IDtoMapper{TDto, TModel}"/>, <see cref="ToModel"/> is only ever used to
/// build a fresh model for <c>UpsertAsync</c>, never to preserve an existing document's <c>Id</c> - the
/// repository upserts by <c>OwnerId</c>, not <c>Id</c>, so a null <c>Id</c> here is harmless (Mongo keeps
/// the existing document's own <c>_id</c> on a matched replace).
/// </summary>
[Mapper]
public partial class UserPreferencesDtoMapper : IDtoMapper<UserPreferencesDto, UserPreferencesModel>
{
    [MapperIgnoreTarget(nameof(UserPreferencesModel.Id))]
    [MapValue(nameof(UserPreferencesModel.OwnerId), "")]
    public partial UserPreferencesModel ToModel(UserPreferencesDto dto);

    [MapperIgnoreSource(nameof(UserPreferencesModel.Id))]
    [MapperIgnoreSource(nameof(UserPreferencesModel.OwnerId))]
    public partial UserPreferencesDto ToDto(UserPreferencesModel model);
}
