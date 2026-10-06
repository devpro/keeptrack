using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="WishlistShareModel"/>.
/// Not an <see cref="IDataRepository{TModel}"/>, since an owner has a handful of links, looked up by owner or token, never paged or searched.
/// </summary>
public interface IWishlistShareRepository
{
    /// <summary>The owner's share links, oldest first.</summary>
    Task<List<WishlistShareModel>> FindAllByOwnerIdAsync(string ownerId);

    /// <summary>The share with this token, or null, for the anonymous shared view.</summary>
    Task<WishlistShareModel?> FindByTokenAsync(string token);

    Task<WishlistShareModel> CreateAsync(WishlistShareModel model);

    /// <summary>Owner-scoped, so a caller revokes only their own share, even by guessing an id.</summary>
    Task DeleteAsync(string id, string ownerId);
}
