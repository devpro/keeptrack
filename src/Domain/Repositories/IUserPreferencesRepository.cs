using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// One preferences document per user, never listed or paged, so a small purpose-built repository rather than an <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IUserPreferencesRepository
{
    /// <summary>
    /// The owner's preferences, or null if never saved, in which case callers use default values rather than writing a document on read.
    /// </summary>
    Task<UserPreferencesModel?> FindByOwnerIdAsync(string ownerId);

    /// <summary>Creates or replaces the owner's preferences document.</summary>
    Task UpsertAsync(UserPreferencesModel model);
}
