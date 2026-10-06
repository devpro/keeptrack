using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class ShareStorageMapper
{
    // the repository stamps CreatedAt on write, ignored here so a model cannot backdate itself, and it is read back as is
    [MapperIgnoreTarget(nameof(Share.CreatedAt))]
    [MapperIgnoreSource(nameof(ShareModel.CreatedAt))]
    public partial Share ToEntity(ShareModel model);

    public partial ShareModel ToModel(Share entity);
}
