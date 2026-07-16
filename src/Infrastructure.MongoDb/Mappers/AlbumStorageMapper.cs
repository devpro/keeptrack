using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class AlbumStorageMapper : IStorageMapper<AlbumModel, Album>
{
    // IsOwned is filter-only (derived from OwnedVersions) - see MovieStorageMapper.
    [MapperIgnoreSource(nameof(AlbumModel.IsOwned))]
    public partial Album ToEntity(AlbumModel model);

    [MapperIgnoreTarget(nameof(AlbumModel.IsOwned))]
    public partial AlbumModel ToModel(Album entity);

    public partial List<AlbumModel> ToModels(List<Album> entities);
}
