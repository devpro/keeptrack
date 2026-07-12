using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class SongStorageMapper : IStorageMapper<SongModel, Song>
{
    public partial Song ToEntity(SongModel model);

    public partial SongModel ToModel(Song entity);

    public partial List<SongModel> ToModels(List<Song> entities);
}
