using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Shared;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

[Trait("Category", "UnitTests")]
public class AppVersionTest
{
    [Fact]
    public void Format_ShortensTheCommitHash()
    {
        AppVersion.Format("2.4.2-alpha-000123+0dbff56febdf601e3e03e6ee5868bb1bc4c8dc71").Should().Be("2.4.2-alpha-000123+0dbff56");
    }

    [Theory]
    [InlineData("2.4.2", "2.4.2")]
    [InlineData("2.4.2+abc", "2.4.2+abc")]
    [InlineData(null, "unknown")]
    [InlineData("", "unknown")]
    public void Format_KeepsAVersionWithoutALongHash(string? informationalVersion, string expected)
    {
        AppVersion.Format(informationalVersion).Should().Be(expected);
    }

    [Fact]
    public void Current_IsTheBlazorAppAssemblyVersion()
    {
        AppVersion.Current.Should().StartWith(typeof(AppVersion).Assembly.GetName().Version!.ToString(3));
    }
}
