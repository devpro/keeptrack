using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less person/actor reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IPersonReferenceRepository
{
    Task<PersonReferenceModel?> FindByIdAsync(string id);

    Task<PersonReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<PersonReferenceModel> UpsertAsync(PersonReferenceModel model);
}
