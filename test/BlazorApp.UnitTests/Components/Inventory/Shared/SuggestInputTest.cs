using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory.Shared;
using Keeptrack.BlazorApp.UnitTests.Components.Shared;
using Microsoft.AspNetCore.Components.Web;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Inventory.Shared;

/// <summary>The keyboard walk over the suggestions: where the first arrow lands, and the wrap at both ends.</summary>
[Trait("Category", "UnitTests")]
public class SuggestInputTest
{
    private const string Active = "kt-autocomplete-item active";

    [Theory]
    [InlineData("ArrowDown", "one")]
    [InlineData("ArrowDown ArrowDown", "two")]
    [InlineData("ArrowDown ArrowDown ArrowDown ArrowDown", "one")]
    [InlineData("ArrowUp", "three")]
    [InlineData("ArrowUp ArrowUp", "two")]
    [InlineData("ArrowDown ArrowUp", "three")]
    public async Task TheArrows_WalkTheSuggestions_AndWrapAtBothEnds(string keys, string highlighted)
    {
        await using var input = await RenderAsync("one", "two", "three");

        foreach (var key in keys.Split(' ')) await input.RaiseAsync("onkeydown", new KeyboardEventArgs { Key = key });

        input.TextsOf("class", Active).Should().Equal(highlighted);
    }

    [Fact]
    public async Task AnArrow_OpensNothing_WhenThereIsNoSuggestion()
    {
        await using var input = await RenderAsync();

        await input.RaiseAsync("onkeydown", new KeyboardEventArgs { Key = "ArrowDown" });

        input.TextsOf("class", Active).Should().BeEmpty();
    }

    private static Task<InteractiveRendering> RenderAsync(params string[] suggestions) =>
        InteractiveRendering.RenderAsync<SuggestInput>(new Dictionary<string, object?> { [nameof(SuggestInput.Suggestions)] = suggestions });
}
