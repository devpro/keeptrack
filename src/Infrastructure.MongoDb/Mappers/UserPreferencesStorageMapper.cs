using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class UserPreferencesStorageMapper : IStorageMapper<UserPreferencesModel, UserPreferences>
{
    public partial UserPreferences ToEntity(UserPreferencesModel model);

    public partial UserPreferencesModel ToModel(UserPreferences entity);

    public partial List<UserPreferencesModel> ToModels(List<UserPreferences> entities);
}
