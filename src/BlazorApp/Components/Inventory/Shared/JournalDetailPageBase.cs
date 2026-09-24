using Keeptrack.BlazorApp.Components.Inventory.Clients;
using Keeptrack.BlazorApp.Components.Shared;
using Keeptrack.BlazorApp.Components.Sharing;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Shared;

/// <summary>
/// Loading, year tabs and the entry modal shared by the journal detail pages: a parent (car, house, health profile) with its dated entries and computed metrics.
/// </summary>
/// <remarks>
/// A concrete page keeps its own <c>[PersistentState]</c> properties and exposes them through <see cref="JournalParent"/>, <see cref="JournalEntries"/> and <see cref="JournalMetrics"/>,
/// since persisted prerender state is keyed by the component that declares it.
/// Every entry mutation reloads the whole journal rather than patching local state, because an entry can change every metric.
/// </remarks>
public abstract class JournalDetailPageBase<TParent, TEntry, TMetrics> : ComponentBase
    where TParent : class, IHasId
    where TEntry : class, IHasId
    where TMetrics : class
{
    [Parameter] public required string Id { get; set; }

    /// <summary>
    /// Set when a recipient views the journal as shared with them, read-only.
    /// Those reads go through the shared-with-me endpoints, since the owner's own endpoints are scoped to the caller and would answer 404.
    /// </summary>
    [Parameter] public string? ShareId { get; set; }

    [Inject] private SharedWithMeApiClient SharedApi { get; set; } = null!;

    protected bool CanEdit => ShareId is null;

    /// <summary>The sharer's display name, for a recipient's breadcrumb.</summary>
    protected string? OwnerName { get; private set; }

    /// <summary>Delay-gated by <see cref="LoadingIndicator"/>, so it only turns on for a load that is genuinely slow.</summary>
    protected bool IsLoading { get; private set; }

    /// <summary>False until a load has finished, so the render Blazor forces before the first fetch resolves is blank rather than a spinner flash.</summary>
    protected bool IsLoaded { get; private set; }

    protected abstract TParent? JournalParent { get; set; }

    protected abstract List<TEntry>? JournalEntries { get; set; }

    protected abstract TMetrics? JournalMetrics { get; set; }

    protected abstract InventoryApiClientBase<TParent> ParentApi { get; }

    protected abstract InventoryApiClientBase<TEntry> EntryApi { get; }

    /// <summary>The entry list's query parameter naming the parent, for example <c>CarId</c>.</summary>
    protected abstract string ParentIdQueryKey { get; }

    protected abstract Task<TMetrics> GetMetricsAsync();

    protected abstract Task<SharedDetailDto<TParent, TEntry, TMetrics>?> GetSharedAsync(SharedWithMeApiClient sharedApi, string shareId);

    protected abstract DateTime EntryDate(TEntry entry);

    protected abstract TEntry NewEntry();

    /// <summary>A copy for the modal to edit, so Cancel leaves the table showing only what was saved.</summary>
    protected abstract TEntry CloneEntry(TEntry entry);

    /// <summary>Rebuilds page-specific state derived from the entries and metrics, after every load.</summary>
    protected virtual void OnJournalLoaded()
    {
    }

    protected List<int> Years { get; private set; } = [];

    protected int SelectedYear { get; private set; }

    protected IReadOnlyList<TEntry> SelectedYearEntries => _entriesByYear.GetValueOrDefault(SelectedYear, []);

    protected TEntry? ModalEntry { get; private set; }

    protected bool ShowModal { get; private set; }

    protected bool ShowDiscardConfirm { get; private set; }

    protected bool IsEditMode => !string.IsNullOrEmpty(ModalEntry?.Id);

    private Dictionary<int, List<TEntry>> _entriesByYear = [];
    private TEntry? _pristineModalEntry;

    protected override async Task OnParametersSetAsync()
    {
        // Already holds this route's journal when prerender state was restored, and an in-circuit navigation to another parent changes the id.
        if (JournalParent?.Id == Id && JournalEntries is not null && JournalMetrics is not null)
        {
            BuildDerivedState();
            IsLoading = false;
            IsLoaded = true;
            return;
        }

        await LoadAsync();
    }

    protected async Task LoadAsync()
    {
        await LoadingIndicator.RunAsync(FetchAsync(), v => IsLoading = v, StateHasChanged);
        IsLoading = false;
        IsLoaded = true;
    }

    protected void SelectYear(int year) => SelectedYear = year;

    protected async Task SaveParentAsync()
    {
        if (JournalParent is null) return;
        await ParentApi.UpdateAsync(JournalParent);
    }

    protected void ShowAddModal() => OpenModal(NewEntry());

    protected void ShowEditModal(TEntry entry) => OpenModal(CloneEntry(entry));

    /// <summary>
    /// The only way to close the modal short of saving, since a click outside it does not: asks first when the entry has unsaved changes.
    /// </summary>
    protected void RequestCancelModal()
    {
        if (DirtyTracking.IsDirty(_pristineModalEntry, ModalEntry)) ShowDiscardConfirm = true;
        else ShowModal = false;
    }

    protected void ConfirmDiscard()
    {
        ShowDiscardConfirm = false;
        ShowModal = false;
    }

    protected void CancelDiscard() => ShowDiscardConfirm = false;

    protected async Task SaveModalEntryAsync()
    {
        if (ModalEntry is null) return;
        if (IsEditMode) await EntryApi.UpdateAsync(ModalEntry);
        else await EntryApi.AddAsync(ModalEntry);

        ShowModal = false;
        await LoadAsync();
    }

    protected async Task DeleteEntryAsync(string id)
    {
        await EntryApi.DeleteAsync(id);
        await LoadAsync();
    }

    private void OpenModal(TEntry entry)
    {
        ModalEntry = entry;
        _pristineModalEntry = CloneEntry(entry);
        ShowModal = true;
    }

    private async Task FetchAsync()
    {
        if (CanEdit)
        {
            JournalParent = await ParentApi.GetOneAsync(Id);
            // The entry query filters on this same id, so it only runs once the parent is known to exist.
            if (JournalParent is null) return;

            var entries = await EntryApi.GetAsync("", 1, int.MaxValue, new Dictionary<string, string> { [ParentIdQueryKey] = Id });
            JournalEntries = NewestFirst(entries.Items);
            JournalMetrics = await GetMetricsAsync();
            BuildDerivedState();
            return;
        }

        // One composite call returns the parent, its entries and metrics, scoped to the sharer once the grant is verified.
        var detail = await GetSharedAsync(SharedApi, ShareId!);
        if (detail is null) return;

        JournalParent = detail.Parent;
        OwnerName = detail.OwnerDisplayName;
        JournalEntries = NewestFirst(detail.Children);
        JournalMetrics = detail.Metrics;
        BuildDerivedState();
    }

    private List<TEntry> NewestFirst(IEnumerable<TEntry> entries) => entries.OrderByDescending(EntryDate).ToList();

    private void BuildDerivedState()
    {
        _entriesByYear = JournalEntries!.GroupBy(e => EntryDate(e).Year).ToDictionary(g => g.Key, g => g.ToList());
        Years = _entriesByYear.Keys.OrderByDescending(y => y).ToList();
        // Keeps the selected tab when it still exists, else the newest year.
        if (!Years.Contains(SelectedYear)) SelectedYear = Years.Count > 0 ? Years[0] : 0;
        OnJournalLoaded();
    }
}
