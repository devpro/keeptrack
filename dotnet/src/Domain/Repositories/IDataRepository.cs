using System.Threading.Tasks;
using KeepTrack.Common.System;

namespace KeepTrack.Domain.Repositories;

public interface IDataRepository<TModel>
    where TModel : IHasIdAndOwnerId
{
    Task<TModel?> FindOneAsync(string id, string ownerId);

    Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input);

    Task<TModel> CreateAsync(TModel model);

    Task<long> UpdateAsync(string id, TModel model, string ownerId);

    Task<long> DeleteAsync(string id, string ownerId);
}
