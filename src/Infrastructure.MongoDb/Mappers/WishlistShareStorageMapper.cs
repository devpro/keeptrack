using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class WishlistShareStorageMapper
{
    // the repository stamps CreatedAt on write, ignored here so a model cannot backdate itself, and it is read back as is
    [MapperIgnoreTarget(nameof(WishlistShare.CreatedAt))]
    [MapperIgnoreSource(nameof(WishlistShareModel.CreatedAt))]
    public partial WishlistShare ToEntity(WishlistShareModel model);

    public partial WishlistShareModel ToModel(WishlistShare entity);
}
