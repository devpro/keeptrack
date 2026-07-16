using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="WishlistShareModel"/> - purpose-built rather than
/// <see cref="IDataRepository{TModel}"/> (one document per owner, looked up by owner or by token,
/// never paged/searched), same reasoning as the owner-less reference repositories.
/// </summary>
public interface IWishlistShareRepository
{
    Task<WishlistShareModel?> FindByOwnerIdAsync(string ownerId);

    /// <summary>The share whose token this is, or null - the anonymous shared-view lookup.</summary>
    Task<WishlistShareModel?> FindByTokenAsync(string token);

    Task<WishlistShareModel> CreateAsync(WishlistShareModel model);

    Task DeleteByOwnerIdAsync(string ownerId);
}
