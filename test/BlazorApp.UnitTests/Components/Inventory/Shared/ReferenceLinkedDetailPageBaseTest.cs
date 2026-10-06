using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory.Clients;
using Keeptrack.BlazorApp.Components.Inventory.Shared;
using Keeptrack.BlazorApp.UnitTests.Components.Shared;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Inventory.Shared;

/// <summary>
/// The pending-link watch of every reference-linked detail page.
/// A re-read replaces the page's model, so it may only happen when it reveals a link:
/// replacing the model while the item is still unlinked swaps the objects a pending action refers to,
/// and removing a copy from the old list then removes nothing and the next save writes it back.
/// </summary>
[Trait("Category", "UnitTests")]
public class ReferenceLinkedDetailPageBaseTest
{
    private sealed class StubHandler(Func<MovieDto> answer) : HttpMessageHandler
    {
        public int Reads { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Reads++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(answer()) });
        }
    }

    /// <summary>A minimal page, since the behaviour under test is entirely the base's.</summary>
    private sealed class TestPage : ReferenceLinkedDetailPageBase<MovieDto, MovieReferenceDto>
    {
        public static readonly List<TestPage> Rendered = [];

        [Parameter] public MovieApiClient Client { get; set; } = null!;

        public MovieDto? Movie { get; private set; }

        protected override InventoryApiClientBase<MovieDto> Api => Client;

        protected override MovieDto? Item { get => Movie; set => Movie = value; }

        protected override MovieReferenceDto? ItemReference { get; set; }

        protected override Task<MovieReferenceDto?> GetReferenceAsync(string referenceId) => Task.FromResult<MovieReferenceDto?>(new MovieReferenceDto { Id = referenceId, Title = "Heat" });

        protected override void OnInitialized() => Rendered.Add(this);

        protected override void BuildRenderTree(RenderTreeBuilder builder) => builder.AddContent(0, Movie?.ReferenceId);
    }

    private static async Task<TestPage> OpenAsync(StubHandler handler)
    {
        TestPage.Rendered.Clear();
        var client = new MovieApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.example") });
        await HtmlRendering.RenderAsync<TestPage>(new Dictionary<string, object?> { ["Id"] = "abc", [nameof(TestPage.Client)] = client });
        return TestPage.Rendered[0];
    }

    [Fact]
    public async Task TheWatch_LeavesTheModelAlone_WhileTheItemIsStillUnlinked()
    {
        var handler = new StubHandler(() => new MovieDto { Id = "abc", Title = "Heat" });
        var page = await OpenAsync(handler);
        var loaded = page.Movie;

        await WaitUntilAsync(() => handler.Reads >= 3);

        page.Movie.Should().BeSameAs(loaded, "the item is still unlinked, so a re-read has nothing to reveal");
    }

    [Fact]
    public async Task TheWatch_ShowsTheLink_OnceItLands()
    {
        var linked = false;
        var handler = new StubHandler(() => new MovieDto { Id = "abc", Title = "Heat", ReferenceId = linked ? "ref-1" : null });
        var page = await OpenAsync(handler);
        linked = true;

        await WaitUntilAsync(() => page.Movie?.ReferenceId == "ref-1");

        page.Movie!.ReferenceId.Should().Be("ref-1");
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++)
        {
            await Task.Delay(100, TestContext.Current.CancellationToken);
        }
    }
}
