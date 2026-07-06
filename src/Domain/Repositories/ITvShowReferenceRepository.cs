using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less TV show reference collection. Deliberately not
/// <see cref="IDataRepository{TModel}"/> - that interface (and its Mongo base class) is hard-constrained
/// to owner-scoped paged CRUD, which doesn't fit a shared lookup table.
/// </summary>
public interface ITvShowReferenceRepository
{
    Task<TvShowReferenceModel?> FindByIdAsync(string id);

    Task<TvShowReferenceModel?> FindByTitleYearAsync(string title, int? year);

    Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model);
}
