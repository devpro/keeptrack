using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class AlbumStorageMapper : IStorageMapper<AlbumModel, Album>
{
    public partial Album ToEntity(AlbumModel model);

    public partial AlbumModel ToModel(Album entity);

    public partial List<AlbumModel> ToModels(List<Album> entities);
}
