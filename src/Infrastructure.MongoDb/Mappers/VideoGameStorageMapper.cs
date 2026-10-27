using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class VideoGameStorageMapper : IStorageMapper<VideoGameModel, VideoGame>
{
    // Platform, State and IsOwned are filter-only members with no entity field, ignored in both directions
    [MapperIgnoreSource(nameof(VideoGameModel.Platform))]
    [MapperIgnoreSource(nameof(VideoGameModel.State))]
    [MapperIgnoreSource(nameof(VideoGameModel.IsOwned))]
    public partial VideoGame ToEntity(VideoGameModel model);

    [MapperIgnoreTarget(nameof(VideoGameModel.Platform))]
    [MapperIgnoreTarget(nameof(VideoGameModel.State))]
    [MapperIgnoreTarget(nameof(VideoGameModel.IsOwned))]
    public partial VideoGameModel ToModel(VideoGame entity);

    public partial List<VideoGameModel> ToModels(List<VideoGame> entities);
}
