using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Shared;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>Only the first character of the title decides, and nothing is better than a meaningless one.</summary>
[Trait("Category", "UnitTests")]
public class CoverPlaceholderTest
{
    [Theory]
    [InlineData("heat", ">H<")]
    [InlineData("  heat", ">H<")]
    [InlineData("1984", ">1<")]
    [InlineData("\U00020000 tale", ">&#x20000;<")]
    public async Task TheFirstLetterOrDigit_IsShown(string title, string expected) =>
        (await RenderAsync(title)).Should().Contain(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    [InlineData("…And Justice for All")]
    [InlineData("🎬 Heat")]
    public async Task AnyOtherTitle_ShowsNothing(string? title) =>
        (await RenderAsync(title)).Trim().Should().BeEmpty();

    private static Task<string> RenderAsync(string? title) =>
        HtmlRendering.RenderAsync<CoverPlaceholder>(new Dictionary<string, object?> { [nameof(CoverPlaceholder.Title)] = title });
}
