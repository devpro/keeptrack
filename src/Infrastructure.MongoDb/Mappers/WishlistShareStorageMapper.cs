using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class WishlistShareStorageMapper
{
    // CreatedAt is stamped by the repository on the write side (ignored here so a model can't
    // ante-date itself) and mapped back plainly on the read side - see BackgroundJobStorageMapper.
    [MapperIgnoreTarget(nameof(WishlistShare.CreatedAt))]
    [MapperIgnoreSource(nameof(WishlistShareModel.CreatedAt))]
    public partial WishlistShare ToEntity(WishlistShareModel model);

    public partial WishlistShareModel ToModel(WishlistShare entity);
}
