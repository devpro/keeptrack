using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// <see cref="ToModel"/> only builds a model for <c>UpsertAsync</c>, which upserts by <c>OwnerId</c>, so a null <c>Id</c> is harmless: MongoDB keeps the existing <c>_id</c> on a matched replace.
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
