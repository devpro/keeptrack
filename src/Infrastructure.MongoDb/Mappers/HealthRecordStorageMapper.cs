using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class HealthRecordStorageMapper : IStorageMapper<HealthRecordModel, HealthRecord>
{
    // a full DateTime on both sides, since an appointment's time is real data, so CommonStorageMappings does not apply and the UTC kind the driver requires is stamped here
    [MapProperty(nameof(HealthRecordModel.HistoryDate), nameof(HealthRecord.HistoryDate), Use = nameof(ToUtcDateTime))]
    public partial HealthRecord ToEntity(HealthRecordModel model);

    public partial HealthRecordModel ToModel(HealthRecord entity);

    public partial List<HealthRecordModel> ToModels(List<HealthRecord> entities);

    [UserMapping(Default = false)]
    private static DateTime ToUtcDateTime(DateTime dateTime) => DateTime.SpecifyKind(dateTime, DateTimeKind.Utc);
}
