using System.Threading.Tasks;
using KeepTrack.Common.Collections.Generic;
using KeepTrack.Domain.Models;

namespace KeepTrack.Domain.Repositories;

public interface IDataRepository<T> where T : IDataModel
{
    Task<T?> FindOneAsync(string id, string ownerId);

    Task<PagedResult<T>> FindAllAsync(string ownerId, int page, int pageSize, string? search, T input);

    Task<T> CreateAsync(T model);

    Task<long> UpdateAsync(string id, T model, string ownerId);

    Task<long> DeleteAsync(string id, string ownerId);
}
