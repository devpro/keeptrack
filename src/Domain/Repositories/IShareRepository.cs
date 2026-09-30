using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="ShareModel"/> - purpose-built rather than <see cref="IDataRepository{TModel}"/>
/// (a handful of grants per owner, looked up by owner or by recipient email, never paged/searched), the same
/// reasoning as <see cref="IWishlistShareRepository"/>.
/// </summary>
public interface IShareRepository
{
    /// <summary>The grants this owner has issued, oldest first - the "who did I share with" list.</summary>
    Task<List<ShareModel>> FindAllByOwnerIdAsync(string ownerId);

    /// <summary>Every grant addressed to this recipient email, oldest first - the "shared with me" list.</summary>
    Task<List<ShareModel>> FindAllByRecipientEmailAsync(string recipientEmail);

    /// <summary>A single grant by id, or null - the recipient-email match is enforced by the caller.</summary>
    Task<ShareModel?> FindByIdAsync(string id);

    Task<ShareModel> CreateAsync(ShareModel model);

    /// <summary>Owner-scoped: a caller can only ever revoke their own grant, even by guessing an id.</summary>
    Task DeleteAsync(string id, string ownerId);
}
