using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="WishlistShareModel"/> - purpose-built rather than
/// <see cref="IDataRepository{TModel}"/> (a handful of documents per owner, looked up by owner or by
/// token, never paged/searched), same reasoning as the owner-less reference repositories.
/// </summary>
public interface IWishlistShareRepository
{
    /// <summary>The owner's shares, oldest first - the "who did I share this with" list.</summary>
    Task<List<WishlistShareModel>> FindAllByOwnerIdAsync(string ownerId);

    /// <summary>The share whose token this is, or null - the anonymous shared-view lookup.</summary>
    Task<WishlistShareModel?> FindByTokenAsync(string token);

    Task<WishlistShareModel> CreateAsync(WishlistShareModel model);

    /// <summary>Owner-scoped: a caller can only ever revoke their own share, even by guessing an id.</summary>
    Task DeleteAsync(string id, string ownerId);
}
