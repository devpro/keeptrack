using Keeptrack.BlazorApp.Components.Shared;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

namespace Keeptrack.BlazorApp.Components.Inventory;

public abstract class InventoryPageBase<TDto> : ComponentBase
    where TDto : IHasId, new()
{
    private const int PageSize = 20;

    // Public properties (a framework requirement for [PersistentState]): the page loaded during the
    // prerender pass is carried over to the interactive circuit, so the first interactive render reuses
    // it instead of resetting to the spinner and re-fetching - same pattern as the detail pages
    // (MovieDetail, etc.). Items is nullable (no property initializer) so [PersistentState] restoration
    // isn't fighting a default value - markup falls back to an empty list via "Items ?? []", same as
    // every other nullable persisted list in this codebase. LoadedQuery is the query signature
    // Items/TotalCount were loaded for, so a restore only skips the reload when it still matches the
    // current search/filter/sort/page - any of those changing must still trigger a real reload.
    [PersistentState]
    public List<TDto>? Items { get; set; }

    [PersistentState]
    public long TotalCount { get; set; }

    [PersistentState]
    public string? LoadedQuery { get; set; }

    protected TDto _form = new();

    protected bool _showForm;

    // _loading is delay-gated (see LoadingIndicator) and only turns on for a load that's genuinely slow.
    // _loaded tracks whether a load attempt has finished at all, fresh or restored from persisted
    // prerender state - both default false so the forced render Blazor triggers right after the
    // synchronous prefix of OnParametersSetAsync (before any awaited fetch resolves) shows blank instead
    // of a spinner flash on every navigation to this page.
    protected bool _loading;

    protected bool _loaded;

    protected string? _error;

    protected string _search = "";

    protected string _sort = "";

    // View mode ("" = list, "grid" = thumbnails) is a global user preference, not list state: it never
    // changes which items are shown or their order, only their presentation. So it lives in the shared,
    // circuit-scoped ListViewPreference (seeded once from localStorage) rather than in the URL/query
    // signature - flipping it must never refetch, and it carries to every list page for the session.
    protected string _view = "";

    protected int _page = 1;

    protected int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);

    [Inject] protected NavigationManager Navigation { get; set; } = null!;

    [Inject] protected ListViewPreference ViewPreference { get; set; } = null!;

    /// <summary>
    /// List state (search, page, and each page's own filters) lives in the URL query string, so that
    /// opening an item's detail page and navigating back restores the exact list position instead of
    /// resetting to an unfiltered page 1 - and a filtered position is bookmarkable/shareable for free.
    /// </summary>
    [SupplyParameterFromQuery(Name = "search")]
    public string? SearchQuery { get; set; }

    [SupplyParameterFromQuery(Name = "page")]
    public int? PageQuery { get; set; }

    [SupplyParameterFromQuery(Name = "sort")]
    public string? SortQuery { get; set; }

    protected abstract InventoryApiClientBase<TDto> Api { get; }

    /// <summary>
    /// The list page's own route ("/movies", "/books", ...), which is also every item's detail-route prefix -
    /// creating an item navigates straight to "{ListRoute}/{id}" so the rest of the fields can be filled in
    /// on the detail page, instead of burying them all in the Add form.
    /// </summary>
    protected abstract string ListRoute { get; }

    /// <summary>
    /// Extra query parameters beyond search/page/pageSize - null by default. Override in a page that
    /// needs its own filter (e.g. a status dropdown) instead of reimplementing paging/search from scratch.
    /// </summary>
    protected virtual IReadOnlyDictionary<string, string>? ExtraQuery => null;

    /// <summary>
    /// The sort key used when the URL carries none - "" (newest-first) for every page unless overridden.
    /// Health/House/Car list themselves by person/vehicle/property name rather than creation order, so
    /// their pages override this to <see cref="ListSort.Title"/> instead.
    /// </summary>
    protected virtual string DefaultSort => "";

    /// <summary>
    /// Runs on the initial load and again whenever the router supplies new query-parameter values
    /// (a filter/page click's NavigateTo, but also browser back/forward), so every way of changing
    /// list state goes through this single reload path. The signature check keeps unrelated
    /// parameter updates (e.g. a cascading auth-state refresh) from re-fetching the same query.
    /// </summary>
    protected override async Task OnParametersSetAsync()
    {
        _search = SearchQuery ?? "";
        _sort = SortQuery ?? DefaultSort;
        _view = ViewPreference.View;
        _page = PageQuery is > 0 ? PageQuery.Value : 1;
        var query = BuildQuerySignature();

        // Items/TotalCount already hold this exact query's results when [PersistentState] restored the
        // prerendered data - the signature check keeps this skip from also swallowing a genuine
        // search/filter/sort/page change (a different signature) or an unrelated parameter update (e.g.
        // a cascading auth-state refresh), both of which must still reload.
        if (query == LoadedQuery)
        {
            _loading = false;
            _loaded = true;
            return;
        }

        LoadedQuery = query;
        await LoadAsync();
    }

    protected void OnSearchChanged(string value) => _search = value;

    protected void OnSearchKeyUp(KeyboardEventArgs e)
    {
        if (e.Key == "Enter")
        {
            ApplyQueryChanges(new Dictionary<string, object?>
            {
                ["search"] = string.IsNullOrWhiteSpace(_search) ? null : _search,
                ["page"] = null,
            });
        }
    }

    protected void ClearSearch()
    {
        _search = "";
        ApplyQueryChanges(new Dictionary<string, object?> { ["search"] = null, ["page"] = null });
    }

    protected void GoToPage(int page) =>
        ApplyQueryChanges(new Dictionary<string, object?> { ["page"] = page <= 1 ? null : page });

    /// <summary>Toggles a boolean filter query parameter (present = on, removed = off) and resets to page 1.</summary>
    protected void ToggleFilter(string name, bool current) =>
        ApplyQueryChanges(new Dictionary<string, object?> { [name] = current ? null : true, ["page"] = null });

    /// <summary>Sets (or clears, when null) a filter query parameter and resets to page 1.</summary>
    protected void SetFilter(string name, string? value) =>
        ApplyQueryChanges(new Dictionary<string, object?> { [name] = value, ["page"] = null });

    /// <summary>
    /// Applies a sort key from the list's sort picker ("" = the newest-first default, which keeps the
    /// URL clean of a redundant parameter) and resets to page 1, through the same URL-navigation path
    /// as every other list-state change.
    /// </summary>
    protected void SetSort(string value) =>
        ApplyQueryChanges(new Dictionary<string, object?> { ["sort"] = string.IsNullOrEmpty(value) ? null : value, ["page"] = null });

    /// <summary>
    /// Adopts a new view reported by the <see cref="ListViewToggle"/> (which owns persisting it to the
    /// shared <see cref="ViewPreference"/> and localStorage). This is a pure presentation change over the
    /// already-loaded page, so it just re-renders in place - no navigation, no refetch.
    /// </summary>
    protected void SetView(string value) => _view = value;

    /// <summary>
    /// Navigates to the current list URL with the given query-parameter changes applied (a null value
    /// removes the parameter). The actual reload happens in <see cref="OnParametersSetAsync"/> once the
    /// router supplies the new values - never here - so a button click and browser back/forward follow
    /// the exact same code path.
    /// </summary>
    protected void ApplyQueryChanges(IReadOnlyDictionary<string, object?> changes) =>
        Navigation.NavigateTo(Navigation.GetUriWithQueryParameters(changes));

    protected void ShowAddForm()
    {
        _form = new TDto();
        _showForm = true;
    }

    protected void CancelForm()
    {
        _showForm = false;
        _error = null;
    }

    protected async Task SaveAsync()
    {
        try
        {
            var created = await Api.AddAsync(_form);
            await WaitForReferenceMatchAsync(created);
            Navigation.NavigateTo($"{ListRoute}/{created.Id}");
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

    /// <summary>
    /// Whether the Add form is holding back its navigation while the new item is matched to reference data.
    /// </summary>
    protected bool MatchingNewItem { get; private set; }

    /// <summary>
    /// Holds the Add form open until a newly created item has been matched to reference data, so its detail page opens already showing the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Matching happens on the server as a detached background task, which cannot be awaited there: it makes a chain of provider calls, and a slow or dead provider would otherwise hold up a create for the resilience pipeline's full timeout - or hold up a bulk import for that timeout per item.
    /// Waiting on the client instead keeps the create as fast and as reliable as it was and puts the delay somewhere it can be bounded and shown.
    /// </para>
    /// <para>
    /// Waiting at all is a deliberate UX choice: without it the detail page opens unmatched and the cover, rating and synopsis appear a second or two later, or don't, depending on how quickly the provider answered.
    /// A short, predictable wait with a spinner is better than a result that pops in at an unpredictable moment - the owner's call, and it also removes the window in which editing a field could race the match.
    /// </para>
    /// <para>
    /// It gives up quietly rather than blocking: the item exists either way, most items have no match to find, and the detail page's own watcher picks up a late arrival.
    /// Only the five reference-linked types wait at all - everything else fails the type test and navigates immediately.
    /// </para>
    /// </remarks>
    private async Task WaitForReferenceMatchAsync(TDto created)
    {
        if (created is not IReferenceLinkedDto || string.IsNullOrEmpty(created.Id)) return;

        MatchingNewItem = true;
        StateHasChanged();
        try
        {
            for (var attempt = 0; attempt < MatchAttempts; attempt++)
            {
                await Task.Delay(MatchPollInterval);
                if (await Api.GetOneAsync(created.Id) is IReferenceLinkedDto item && !string.IsNullOrEmpty(item.ReferenceId)) return;
            }
        }
        finally
        {
            MatchingNewItem = false;
        }
    }

    private static readonly TimeSpan MatchPollInterval = TimeSpan.FromMilliseconds(400);

    /// <summary>
    /// How long the Add form waits for a match before opening the detail page anyway - two seconds, and never more.
    /// </summary>
    /// <remarks>
    /// This is a bound on how long a person is made to look at a spinner, not an estimate of how long matching takes, so it is set from what is tolerable rather than from what the provider needs.
    /// A resolve that has not landed in two seconds is left to finish on its own; the detail page's own watcher shows it when it arrives, which is the behaviour this wait improves on rather than replaces.
    /// </remarks>
    private const int MatchAttempts = 5;

    protected async Task DeleteAsync(string id)
    {
        try
        {
            await Api.DeleteAsync(id);
            await LoadAsync();
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

    protected async Task LoadAsync()
    {
        try
        {
            await LoadingIndicator.RunAsync(FetchAsync(), v => _loading = v, StateHasChanged);
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
        finally
        {
            _loading = false;
            _loaded = true;
        }
    }

    private async Task FetchAsync()
    {
        var result = await Api.GetAsync(_search, _page, PageSize, ExtraQuery, _sort);
        Items = result.Items;
        TotalCount = result.TotalCount;
    }

    private string BuildQuerySignature()
    {
        var extra = ExtraQuery is null ? "" : string.Join('&', ExtraQuery.Select(pair => $"{pair.Key}={pair.Value}"));
        return $"{_search}|{_page}|{_sort}|{extra}";
    }
}
