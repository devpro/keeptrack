using System;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// A provider id for a synthetic reference document, unique to the call.
/// <para>
/// A hardcoded id (<c>"1"</c>, <c>"OL1W"</c>) is a correctness problem: <c>scripts/mongodb-create-index.js</c> makes <c>external_ids.{provider}</c> unique where present, and xunit runs test classes in parallel.
/// Two classes inserting a tvshow_reference with <c>tmdb: "1"</c> would race into a duplicate-key error, and one leaked document would block every later run.
/// </para>
/// <para>
/// The value only has to be opaque and unique, since no test calls a real provider with it.
/// </para>
/// </summary>
internal static class TestExternalId
{
    public static string New() => $"test-{Guid.NewGuid():N}";
}
