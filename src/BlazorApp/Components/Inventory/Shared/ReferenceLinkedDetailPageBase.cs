using Keeptrack.BlazorApp.Components.Inventory.Clients;
using Keeptrack.BlazorApp.Components.Shared;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Shared;

/// <summary>
/// Loading, saving and reference linking shared by the detail pages of the five reference-linked types.
/// </summary>
/// <remarks>
/// A concrete page keeps its own <c>[PersistentState]</c> properties and exposes them through <see cref="Item"/> and <see cref="ItemReference"/>,
/// since persisted prerender state is keyed by the component that declares it.
/// </remarks>
public abstract class ReferenceLinkedDetailPageBase<TDto, TReferenceDto> : ComponentBase
    where TDto : class, IHasId, IReferenceLinkedDto
    where TReferenceDto : class
{
    [Parameter] public required string Id { get; set; }

    protected abstract InventoryApiClientBase<TDto> Api { get; }

    protected abstract TDto? Item { get; set; }

    protected abstract TReferenceDto? ItemReference { get; set; }

    protected abstract Task<TReferenceDto?> GetReferenceAsync(string referenceId);

    /// <summary>
    /// Loads what the page shows besides the item and its reference, once per load rather than on every read of the item.
    /// Runs after the item is read, so it can depend on it, and runs when the item is missing too.
    /// </summary>
    protected virtual Task LoadExtrasAsync() => Task.CompletedTask;

    /// <summary>
    /// Rebuilds state derived from the item and its reference, after every read of them.
    /// </summary>
    protected virtual void OnItemLoaded()
    {
    }

    /// <summary>
    /// Delay-gated by <see cref="LoadingIndicator"/>, so it only turns on for a load that is genuinely slow.
    /// </summary>
    protected bool IsLoading { get; private set; }

    /// <summary>
    /// Whether a load has finished, fresh or restored from prerender state.
    /// False until then, so the render Blazor forces before the first fetch resolves is blank rather than a spinner flash.
    /// </summary>
    protected bool IsLoaded { get; private set; }

    /// <summary>
    /// Reveals the admin search panel.
    /// Set by a check for a match that came back empty, never by the item merely being unlinked, or the panel would sit above every unlinked item.
    /// </summary>
    protected bool ShowLinker { get; private set; }

    /// <summary>
    /// Whether the page no longer holds exactly what it loaded, which stops the pending-link watch from reading over the change.
    /// </summary>
    private bool _edited;

    protected override async Task OnParametersSetAsync()
    {
        // Already holds this route's item when prerender state was restored, and an in-circuit navigation to another item changes the id.
        if (Item?.Id == Id)
        {
            IsLoading = false;
            IsLoaded = true;
            return;
        }

        await LoadAsync();
    }

    protected async Task LoadAsync()
    {
        ShowLinker = false;
        _edited = false;
        await LoadingIndicator.RunAsync(FetchAsync(), v => IsLoading = v, StateHasChanged);
        IsLoading = false;
        IsLoaded = true;

        // Not awaited: a just-created item is still being resolved on the server, and the page renders now rather than waiting for that.
        _ = PendingReferenceLink.WatchAsync(
            () => !string.IsNullOrEmpty(Item?.ReferenceId),
            FetchPendingLinkAsync,
            () => InvokeAsync(StateHasChanged),
            () => !_edited);
    }

    /// <summary>
    /// Records a change the server may not hold yet.
    /// Called before the request that makes it, since the read it has to beat can already be in flight.
    /// </summary>
    protected void MarkEdited() => _edited = true;

    /// <summary>
    /// Every field edit mutates <see cref="Item"/> and then writes the whole item back.
    /// </summary>
    protected async Task SaveAsync()
    {
        if (Item is null) return;
        MarkEdited();
        await Api.UpdateAsync(Item);
    }

    protected async Task OnReferenceCheckedAsync(bool linked)
    {
        await LoadAsync();
        ShowLinker = !linked;
    }

    private async Task FetchAsync()
    {
        Item = await Api.GetOneAsync(Id);
        ItemReference = await GetReferenceOrNullAsync(Item);
        await LoadExtrasAsync();
        OnItemLoaded();
    }

    /// <summary>
    /// The watch's own read, which replaces the page's model only when it reveals a link.
    /// Replacing it otherwise swaps the objects a pending action holds, such as a copy awaiting its removal confirmation,
    /// which then removes nothing from the new list and is written back by the next save.
    /// The answer is also thrown away when a save landed while the read was in flight, since it describes the item before that save.
    /// </summary>
    private async Task FetchPendingLinkAsync()
    {
        var item = await Api.GetOneAsync(Id);
        if (string.IsNullOrEmpty(item?.ReferenceId)) return;

        var reference = await GetReferenceOrNullAsync(item);
        if (_edited) return;

        Item = item;
        ItemReference = reference;
        OnItemLoaded();
    }

    private async Task<TReferenceDto?> GetReferenceOrNullAsync(TDto? item) =>
        string.IsNullOrEmpty(item?.ReferenceId) ? null : await GetReferenceAsync(item.ReferenceId);
}
