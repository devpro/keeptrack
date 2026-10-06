using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class BackgroundJobStorageMapper
{
    // JobId (Guid) maps to Id (string) through Mapperly's built-in conversion.
    // The repository stamps CreatedAt on write, ignored here so a model cannot backdate itself, and it is read back as is.
    [MapProperty(nameof(BackgroundJobModel.JobId), nameof(BackgroundJob.Id))]
    [MapperIgnoreTarget(nameof(BackgroundJob.CreatedAt))]
    [MapperIgnoreSource(nameof(BackgroundJobModel.CreatedAt))]
    public partial BackgroundJob ToEntity(BackgroundJobModel model);

    [MapProperty(nameof(BackgroundJob.Id), nameof(BackgroundJobModel.JobId))]
    public partial BackgroundJobModel ToModel(BackgroundJob entity);
}
