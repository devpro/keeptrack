using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class VideoGameStorageMapper : IStorageMapper<VideoGameModel, VideoGame>
{
    // Platform/State are filter-only members on VideoGameModel with no matching entity field - see
    // VideoGameModel.Platform/State's own doc comments. Ignored on both directions: as an unmapped
    // target on the read side, as an unmapped source (nothing to write) on the write side.
    [MapperIgnoreSource(nameof(VideoGameModel.Platform))]
    [MapperIgnoreSource(nameof(VideoGameModel.State))]
    public partial VideoGame ToEntity(VideoGameModel model);

    [MapperIgnoreTarget(nameof(VideoGameModel.Platform))]
    [MapperIgnoreTarget(nameof(VideoGameModel.State))]
    public partial VideoGameModel ToModel(VideoGame entity);

    public partial List<VideoGameModel> ToModels(List<VideoGame> entities);
}
