using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>
/// Renders a component or a fragment to static HTML with the framework's own <see cref="HtmlRenderer"/>, so markup is asserted without a browser or a test library.
/// </summary>
internal static class HtmlRendering
{
    public static Task<string> RenderAsync<TComponent>(IDictionary<string, object?> parameters) where TComponent : IComponent =>
        RenderAsync<TComponent>(ParameterView.FromDictionary(parameters));

    public static Task<string> RenderAsync(RenderFragment fragment) =>
        RenderAsync<FragmentHost>(ParameterView.FromDictionary(new Dictionary<string, object?> { [nameof(FragmentHost.Content)] = fragment }));

    private static async Task<string> RenderAsync<TComponent>(ParameterView parameters) where TComponent : IComponent
    {
        var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        await using var renderer = new HtmlRenderer(services, services.GetRequiredService<ILoggerFactory>());
        return await renderer.Dispatcher.InvokeAsync(async () => (await renderer.RenderComponentAsync<TComponent>(parameters)).ToHtmlString());
    }

    private sealed class FragmentHost : ComponentBase
    {
        [Parameter] public RenderFragment? Content { get; set; }

        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder builder) => builder.AddContent(0, Content);
    }
}
