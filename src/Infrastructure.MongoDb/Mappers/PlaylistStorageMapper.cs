using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class PlaylistStorageMapper : IStorageMapper<PlaylistModel, Playlist>
{
    public partial Playlist ToEntity(PlaylistModel model);

    public partial PlaylistModel ToModel(Playlist entity);

    public partial List<PlaylistModel> ToModels(List<Playlist> entities);
}
