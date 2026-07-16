using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class WishlistShareStorageMapper
{
    public partial WishlistShare ToEntity(WishlistShareModel model);

    public partial WishlistShareModel ToModel(WishlistShare entity);
}
