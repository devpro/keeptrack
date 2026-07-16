using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class BackgroundJobStorageMapper
{
    // JobId (Guid) <-> Id (string): Mapperly's built-in Guid/string conversion, renamed across the pair.
    // CreatedAt is stamped by the repository on the write side (ignored here so a model can't ante-date
    // itself) and mapped back plainly on the read side.
    [MapProperty(nameof(BackgroundJobModel.JobId), nameof(BackgroundJob.Id))]
    [MapperIgnoreTarget(nameof(BackgroundJob.CreatedAt))]
    [MapperIgnoreSource(nameof(BackgroundJobModel.CreatedAt))]
    public partial BackgroundJob ToEntity(BackgroundJobModel model);

    [MapProperty(nameof(BackgroundJob.Id), nameof(BackgroundJobModel.JobId))]
    public partial BackgroundJobModel ToModel(BackgroundJob entity);
}
