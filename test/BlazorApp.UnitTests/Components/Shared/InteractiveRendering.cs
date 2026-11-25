using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.HtmlRendering.Infrastructure;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// The render tree is the only public way to an event handler id without a browser or a test library, and a framework change breaks the build of this one file.
#pragma warning disable BL0006

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>
/// Renders one component with its children and raises events on their elements, which <see cref="HtmlRendering"/> cannot, so behavior is asserted without a browser.
/// </summary>
internal sealed class InteractiveRendering(IServiceProvider services, ILoggerFactory loggerFactory) : StaticHtmlRenderer(services, loggerFactory)
{
    private int _componentId;

    public static async Task<InteractiveRendering> RenderAsync<TComponent>(IDictionary<string, object?> parameters, Action<IServiceCollection>? configure = null)
        where TComponent : IComponent
    {
        var collection = new ServiceCollection().AddLogging();
        configure?.Invoke(collection);
        var services = collection.BuildServiceProvider();
        var renderer = new InteractiveRendering(services, services.GetRequiredService<ILoggerFactory>());
        await renderer.Dispatcher.InvokeAsync(async () =>
        {
            renderer._componentId = renderer.AssignRootComponentId(renderer.InstantiateComponent(typeof(TComponent)));
            await renderer.RenderRootComponentAsync(renderer._componentId, ParameterView.FromDictionary(parameters));
        });
        return renderer;
    }

    /// <summary>
    /// Raises <paramref name="eventName"/> on the first element handling it, or on the first that also carries <paramref name="marker"/>,
    /// as the value of one of its attributes or as its text.
    /// </summary>
    public Task RaiseAsync(string eventName, EventArgs args, string? marker = null) => Dispatcher.InvokeAsync(() =>
    {
        var element = Elements().FirstOrDefault(e => e.HandlerOf(eventName) != 0 && (marker is null || e.Carries(marker)))
            ?? throw new InvalidOperationException($"No element handles {eventName} and carries '{marker}'.");
        return DispatchEventAsync(element.HandlerOf(eventName), null, args);
    });

    public Task ClickAsync(string marker) => RaiseAsync("onclick", new MouseEventArgs(), marker);

    public Task ChangeAsync(object? value, string? marker = null) => RaiseAsync("onchange", new ChangeEventArgs { Value = value }, marker);

    /// <summary>The text of each element carrying exactly the attribute and value given.</summary>
    public List<string> TextsOf(string attribute, string value) =>
        Elements().Where(e => e.Attributes.Any(a => a.AttributeName == attribute && a.AttributeValue as string == value)).Select(e => e.Text).ToList();

    /// <summary>
    /// Whether any element carries <paramref name="marker"/>, as <see cref="RaiseAsync"/> reads it.
    /// An element with nothing dynamic is compiled into a raw markup frame, so those are read too.
    /// </summary>
    public bool Shows(string marker)
    {
        var markup = new List<string>();
        return Elements(markup).Any(e => e.Carries(marker)) || markup.Exists(m => m.Contains($">{marker}<", StringComparison.Ordinal));
    }

    private List<Element> Elements(List<string>? markup = null)
    {
        var elements = new List<Element>();
        Collect(_componentId, elements, markup);
        return elements;
    }

    private void Collect(int componentId, List<Element> elements, List<string>? markup)
    {
        var range = GetCurrentRenderTreeFrames(componentId);
        var frames = range.Array[..range.Count];
        for (var i = 0; i < frames.Length; i++)
        {
            if (frames[i].FrameType == RenderTreeFrameType.Element) elements.Add(new Element(frames[i..(i + frames[i].ElementSubtreeLength)]));
            if (frames[i].FrameType == RenderTreeFrameType.Component) Collect(frames[i].ComponentId, elements, markup);
            if (frames[i].FrameType == RenderTreeFrameType.Markup) markup?.Add(frames[i].MarkupContent);
        }
    }

    private sealed class Element(RenderTreeFrame[] frames)
    {
        public List<RenderTreeFrame> Attributes { get; } = frames.Skip(1).TakeWhile(f => f.FrameType == RenderTreeFrameType.Attribute).ToList();

        public string Text { get; } = string.Concat(frames.Select(f => f.FrameType switch
        {
            RenderTreeFrameType.Text => f.TextContent,
            RenderTreeFrameType.Markup => f.MarkupContent,
            _ => string.Empty
        })).Trim();

        public ulong HandlerOf(string eventName) => Attributes.Find(a => a.AttributeName == eventName).AttributeEventHandlerId;

        public bool Carries(string marker) => Text == marker || Attributes.Exists(a => a.AttributeValue as string == marker);
    }
}
