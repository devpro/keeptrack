using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// A single per-user preferences document, not a full owner-scoped CRUD collection (there's exactly one
/// document per owner, never listed/paged) - a small purpose-built repository like
/// <see cref="ILeaseRepository"/>, rather than forced through <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IUserPreferencesRepository
{
    /// <summary>
    /// The owner's preferences, or null if they've never saved any - callers should fall back to an
    /// all-default instance rather than writing one on read.
    /// </summary>
    Task<UserPreferencesModel?> FindByOwnerIdAsync(string ownerId);

    /// <summary>
    /// Creates or fully replaces the owner's preferences document.
    /// </summary>
    Task UpsertAsync(UserPreferencesModel model);
}
