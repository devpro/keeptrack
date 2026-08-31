using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Repositories;

public interface IDataRepository<TModel>
    where TModel : IHasIdAndOwnerId
{
    Task<TModel?> FindOneAsync(string id, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Owner-scoped paged read. <paramref name="sort"/> is a <see cref="ListSort"/> key; null/empty (or a
    /// key the collection doesn't support) means the default order, newest first. Every page read is
    /// deterministically ordered - an unsorted skip/limit page could duplicate or drop items across pages.
    /// </summary>
    Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input, string? sort = null, CancellationToken cancellationToken = default);

    /// <summary>How many items this owner has in total - backs the Home page's collection overview.</summary>
    Task<long> CountAsync(string ownerId, CancellationToken cancellationToken = default);

    Task<TModel> CreateAsync(TModel model, CancellationToken cancellationToken = default);

    Task<long> UpdateAsync(string id, TModel model, string ownerId, CancellationToken cancellationToken = default);

    Task<long> DeleteAsync(string id, string ownerId, CancellationToken cancellationToken = default);
}
