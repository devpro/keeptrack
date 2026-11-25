using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory;
using Keeptrack.BlazorApp.Components.Sharing;
using Keeptrack.BlazorApp.UnitTests.Components.Shared;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Sharing;

/// <summary>The one action of a shared row: none for a view-only category, a badge for an owned item, else "add".</summary>
[Trait("Category", "UnitTests")]
public class SharedCategoryListTest
{
    private const string Add = "Add to my collection";

    private const string Badge = "✓ In collection";

    [Fact]
    public async Task AViewOnlyCategory_HasNoAction_EvenForAnOwnedItem()
    {
        await using var list = await RenderAsync(null, "m1");

        list.Shows("Heat").Should().BeTrue();
        list.Shows(Add).Should().BeFalse();
        list.Shows(Badge).Should().BeFalse();
    }

    [Fact]
    public async Task AnOwnedItem_ShowsTheBadge()
    {
        await using var list = await RenderAsync(_ => Task.FromResult<CopyResultDto<MovieDto>?>(null), "m1");

        list.Shows(Badge).Should().BeTrue();
        list.Shows(Add).Should().BeFalse();
    }

    [Fact]
    public async Task AddingAnItem_ShowsItIsRunning_ThenTheBadge()
    {
        var copy = new TaskCompletionSource<CopyResultDto<MovieDto>?>();
        await using var list = await RenderAsync(_ => copy.Task);

        var adding = list.ClickAsync(Add);
        list.Shows("Adding").Should().BeTrue();
        copy.SetResult(new CopyResultDto<MovieDto> { Item = new MovieDto { Id = "copy", Title = "Heat" } });
        await adding;

        list.Shows(Badge).Should().BeTrue();
        list.Shows("Adding").Should().BeFalse();
    }

    private static Task<InteractiveRendering> RenderAsync(Func<string, Task<CopyResultDto<MovieDto>?>>? copy, params string[] owned) =>
        InteractiveRendering.RenderAsync<SharedCategoryList<MovieDto>>(
            new Dictionary<string, object?>
            {
                [nameof(SharedCategoryList<MovieDto>.Title)] = "Movies",
                [nameof(SharedCategoryList<MovieDto>.Fetch)] = (Func<SharedListQuery, Task<SharedCategoryPageDto<MovieDto>?>>)(_ =>
                    Task.FromResult<SharedCategoryPageDto<MovieDto>?>(new SharedCategoryPageDto<MovieDto>
                    {
                        Items = [new MovieDto { Id = "m1", Title = "Heat" }],
                        TotalCount = 1,
                        AlreadyInCollectionIds = [.. owned]
                    })),
                [nameof(SharedCategoryList<MovieDto>.Copy)] = copy,
                [nameof(SharedCategoryList<MovieDto>.ItemTitle)] = (Func<MovieDto, string?>)(m => m.Title),
                [nameof(SharedCategoryList<MovieDto>.MetaTemplate)] = (RenderFragment<MovieDto>)(_ => _ => { })
            },
            services => services.AddPageServices().AddSingleton<ListViewPreference>());
}
