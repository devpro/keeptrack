using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.HtmlRendering.Infrastructure;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// The render tree is the only public way to an event handler id without a browser or a test library, and a framework change breaks the build of this one file.
#pragma warning disable BL0006

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>
/// Renders one component and raises events on its elements, which <see cref="HtmlRendering"/> cannot, so keyboard behavior is asserted without a browser.
/// </summary>
internal sealed class InteractiveRendering(IServiceProvider services, ILoggerFactory loggerFactory) : StaticHtmlRenderer(services, loggerFactory)
{
    private int _componentId;

    public static async Task<InteractiveRendering> RenderAsync<TComponent>(IDictionary<string, object?> parameters) where TComponent : IComponent
    {
        var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var renderer = new InteractiveRendering(services, services.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = renderer.InstantiateComponent(typeof(TComponent));
            renderer._componentId = renderer.AssignRootComponentId(component);
            await renderer.RenderRootComponentAsync(renderer._componentId, ParameterView.FromDictionary(parameters));
        });
        return renderer;
    }

    /// <summary>Raises <paramref name="eventName"/> on the first element of the component handling it.</summary>
    public Task RaiseAsync(string eventName, EventArgs args) => Dispatcher.InvokeAsync(() =>
    {
        foreach (var frame in Frames())
        {
            if (frame.FrameType == RenderTreeFrameType.Attribute && frame.AttributeName == eventName && frame.AttributeEventHandlerId != 0)
            {
                return DispatchEventAsync(frame.AttributeEventHandlerId, null, args);
            }
        }

        throw new InvalidOperationException($"No element handles {eventName}.");
    });

    /// <summary>The text of each element carrying exactly the attribute and value given.</summary>
    public List<string> TextsOf(string attribute, string value)
    {
        var texts = new List<string>();
        var frames = Frames();
        for (var i = 0; i < frames.Length; i++)
        {
            if (frames[i].FrameType != RenderTreeFrameType.Attribute || frames[i].AttributeName != attribute || frames[i].AttributeValue as string != value) continue;
            var text = i;
            while (frames[text].FrameType != RenderTreeFrameType.Text) text++;
            texts.Add(frames[text].TextContent);
        }

        return texts;
    }

    private RenderTreeFrame[] Frames()
    {
        var range = GetCurrentRenderTreeFrames(_componentId);
        return range.Array[..range.Count];
    }
}
