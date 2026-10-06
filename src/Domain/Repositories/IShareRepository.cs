using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="ShareModel"/>.
/// Not an <see cref="IDataRepository{TModel}"/>, since an owner has a handful of grants, looked up by owner or recipient email, never paged or searched.
/// </summary>
public interface IShareRepository
{
    /// <summary>The grants this owner issued, oldest first.</summary>
    Task<List<ShareModel>> FindAllByOwnerIdAsync(string ownerId);

    /// <summary>Every grant addressed to this recipient email, oldest first, for the "shared with me" list.</summary>
    Task<List<ShareModel>> FindAllByRecipientEmailAsync(string recipientEmail);

    /// <summary>A single grant by id, or null, the caller enforcing the recipient email match.</summary>
    Task<ShareModel?> FindByIdAsync(string id);

    Task<ShareModel> CreateAsync(ShareModel model);

    /// <summary>Owner-scoped, so a caller revokes only their own grant, even by guessing an id.</summary>
    Task DeleteAsync(string id, string ownerId);
}
