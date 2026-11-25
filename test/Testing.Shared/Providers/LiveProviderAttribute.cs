using System;
using System.Collections.Generic;
using System.Reflection;
using Xunit;
using Xunit.v3;

namespace Keeptrack.Testing.Shared.Providers;

/// <summary>
/// Marks a test, or every test of a class, whose subject is a live provider: it skips unless <see cref="LiveProviders.Enabled"/>.
/// Also a trait, so <c>--filter-trait "Provider=Live"</c> selects exactly those tests.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class LiveProviderAttribute : BeforeAfterTestAttribute, ITraitAttribute
{
    public IReadOnlyCollection<KeyValuePair<string, string>> GetTraits() => [new("Provider", "Live")];

    public override void Before(MethodInfo methodUnderTest, IXunitTest test) =>
        Assert.SkipUnless(LiveProviders.Enabled, "TEST_LIVE_PROVIDERS is not true, and this test calls a live provider.");
}
