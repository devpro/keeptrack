using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared person reference collection (actors, authors, artists).
/// See <see cref="ITvShowReferenceRepository"/> for why it does not extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IPersonReferenceRepository
{
    Task<PersonReferenceModel?> FindByIdAsync(string id);

    Task<PersonReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<PersonReferenceModel> UpsertAsync(PersonReferenceModel model);

    /// <summary>
    /// Every reference document, for the admin export.
    /// An unpaged read is fine, since this shared metadata is bounded and not per tenant.
    /// </summary>
    Task<List<PersonReferenceModel>> FindAllAsync();
}
