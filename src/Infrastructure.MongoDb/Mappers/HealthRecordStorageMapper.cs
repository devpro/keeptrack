using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class HealthRecordStorageMapper : IStorageMapper<HealthRecordModel, HealthRecord>
{
    // HistoryDate is a plain DateTime on both sides (an appointment's time of day is real data, same as
    // CarHistory - the shared DateOnly<->DateTime CommonStorageMappings deliberately doesn't apply), so
    // nothing upstream stamps DateTimeKind.Utc and the Mongo driver's DateTimeSerializer requires it.
    [MapProperty(nameof(HealthRecordModel.HistoryDate), nameof(HealthRecord.HistoryDate), Use = nameof(ToUtcDateTime))]
    public partial HealthRecord ToEntity(HealthRecordModel model);

    public partial HealthRecordModel ToModel(HealthRecord entity);

    public partial List<HealthRecordModel> ToModels(List<HealthRecord> entities);

    [UserMapping(Default = false)]
    private static DateTime ToUtcDateTime(DateTime dateTime) => DateTime.SpecifyKind(dateTime, DateTimeKind.Utc);
}
