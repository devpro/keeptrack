using System;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Shared;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

[Trait("Category", "UnitTests")]
public class DateOnlyInputTest
{
    [Fact]
    public void Parse_ParsesAnHtmlDateInputValue_RegardlessOfCurrentCulture()
    {
        DateOnlyInput.Parse("2026-07-23").Should().Be(new DateOnly(2026, 7, 23));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-date")]
    public void Parse_ReturnsNull_ForMissingOrInvalidInput(object? value)
    {
        DateOnlyInput.Parse(value).Should().BeNull();
    }
}
