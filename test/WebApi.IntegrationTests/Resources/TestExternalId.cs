using System;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// A provider id for a synthetic reference document, unique to the call.
/// <para>
/// Reference fixtures used to hardcode <c>"1"</c> (or <c>"OL1W"</c>), which is now a correctness problem
/// rather than a cosmetic one: <c>scripts/mongodb-create-index.js</c> makes <c>external_ids.{provider}</c>
/// unique where present, and xunit runs test classes in parallel, so two classes both inserting a
/// tvshow_reference with <c>tmdb: "1"</c> race into a duplicate-key error. A shared constant also meant a
/// single leaked document permanently blocked every later run.
/// </para>
/// <para>
/// The value only has to be opaque and unique - nothing in these tests calls a real provider with it.
/// </para>
/// </summary>
internal static class TestExternalId
{
    public static string New() => $"test-{Guid.NewGuid():N}";
}
