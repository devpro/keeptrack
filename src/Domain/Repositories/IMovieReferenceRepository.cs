using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less movie reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IMovieReferenceRepository
{
    Task<MovieReferenceModel?> FindByIdAsync(string id);

    Task<MovieReferenceModel?> FindByTitleYearAsync(string title, int? year);

    Task<MovieReferenceModel> UpsertAsync(MovieReferenceModel model);
}
