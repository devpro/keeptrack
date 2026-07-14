using System;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Shared <c>DateOnly</c> &lt;-&gt; <c>DateTime</c> conversion, attached to any storage mapper that needs
/// it via <c>[UseStaticMapper(typeof(CommonStorageMappings))]</c>. Every Domain model date field is
/// <see cref="DateOnly"/> while its Mongo entity counterpart is <see cref="DateTime"/> - the driver's
/// <c>DateTimeSerializer</c> requires <see cref="DateTimeKind.Utc"/>, so <see cref="ToDateTime"/> stamps
/// it explicitly rather than leaving it <see cref="DateTimeKind.Unspecified"/>.
/// </summary>
public static class CommonStorageMappings
{
    [UserMapping]
    public static DateOnly ToDateOnly(DateTime dateTime)
    {
        return DateOnly.FromDateTime(dateTime);
    }

    [UserMapping]
    public static DateTime ToDateTime(DateOnly dateOnly)
    {
        return dateOnly.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
    }
}
