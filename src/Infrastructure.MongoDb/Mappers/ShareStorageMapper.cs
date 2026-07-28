using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class ShareStorageMapper
{
    // CreatedAt is stamped by the repository on the write side (ignored here so a model can't
    // ante-date itself) and mapped back plainly on the read side - see WishlistShareStorageMapper.
    [MapperIgnoreTarget(nameof(Share.CreatedAt))]
    [MapperIgnoreSource(nameof(ShareModel.CreatedAt))]
    public partial Share ToEntity(ShareModel model);

    public partial ShareModel ToModel(Share entity);
}
