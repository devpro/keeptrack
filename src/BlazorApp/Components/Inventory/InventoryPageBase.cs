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

    // Public properties, as [PersistentState] requires: the page loaded during prerender carries over to the interactive circuit, which reuses it rather than re-fetching, like the detail pages.
    // Items is nullable with no initializer, so restoration doesn't fight a default value, and the markup falls back to "Items ?? []".
    // LoadedQuery is the query signature Items and TotalCount were loaded for, so a restore skips the reload only while it matches the current search, filter, sort and page.
    [PersistentState]
    public List<TDto>? Items { get; set; }

    [PersistentState]
    public long TotalCount { get; set; }

    [PersistentState]
    public string? LoadedQuery { get; set; }

    protected TDto _form = new();

    protected bool _showForm;

    // _loading is delay-gated (see LoadingIndicator) and turns on only for a slow load, and _loaded tracks whether a load has finished, fresh or restored from prerender state.
    // Both default false, so the render Blazor forces after OnParametersSetAsync's synchronous prefix shows blank instead of flashing a spinner on every navigation here.
    protected bool _loading;

    protected bool _loaded;

    protected string? _error;

    protected string _search = "";

    protected string _sort = "";

    // The view mode ("" for list, "grid" for thumbnails) is a user preference, not list state, since it changes only the presentation.
    // It lives in the circuit-scoped ListViewPreference rather than the URL, so flipping it never refetches and it carries to every list page for the session.
    protected string _view = "";

    protected int _page = 1;

    protected int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);

    [Inject] protected NavigationManager Navigation { get; set; } = null!;

    [Inject] protected ListViewPreference ViewPreference { get; set; } = null!;

    /// <summary>
    /// List state (search, page, each page's own filters) lives in the URL query string, so navigating back from a detail page restores the exact list position.
    /// A filtered position can also be bookmarked or shared.
    /// </summary>
    [SupplyParameterFromQuery(Name = "search")]
    public string? SearchQuery { get; set; }

    [SupplyParameterFromQuery(Name = "page")]
    public int? PageQuery { get; set; }

    [SupplyParameterFromQuery(Name = "sort")]
    public string? SortQuery { get; set; }

    protected abstract InventoryApiClientBase<TDto> Api { get; }

    /// <summary>
    /// The list page's own route ("/movies", "/books"...), also every item's detail-route prefix.
    /// Creating an item navigates to "{ListRoute}/{id}", where the other fields are filled in, rather than burying them all in the Add form.
    /// </summary>
    protected abstract string ListRoute { get; }

    /// <summary>
    /// Extra query parameters beyond search, page and pageSize, null by default.
    /// A page with its own filter (a status dropdown) overrides it rather than reimplementing paging and search.
    /// </summary>
    protected virtual IReadOnlyDictionary<string, string>? ExtraQuery => null;

    /// <summary>
    /// The sort key used when the URL carries none, "" (newest first) unless overridden.
    /// Health, House and Car list by name rather than creation order, so their pages override it with <see cref="ListSort.Title"/>.
    /// </summary>
    protected virtual string DefaultSort => "";

    /// <summary>
    /// Runs on the initial load and whenever the router supplies new query values (a filter or page click's NavigateTo, browser back or forward), so every list state change takes this one reload path.
    /// The signature check keeps unrelated parameter updates (a cascading auth-state refresh) from re-fetching the same query.
    /// </summary>
    protected override async Task OnParametersSetAsync()
    {
        _search = SearchQuery ?? "";
        _sort = SortQuery ?? DefaultSort;
        _view = ViewPreference.View;
        _page = PageQuery is > 0 ? PageQuery.Value : 1;
        var query = BuildQuerySignature();

        // Items and TotalCount already hold this query's results when [PersistentState] restored the prerendered data.
        // A genuine search, filter, sort or page change has a different signature, so it still reloads.
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

    /// <summary>Toggles a boolean filter query parameter (present when on, removed when off) and resets to page 1.</summary>
    protected void ToggleFilter(string name, bool current) =>
        ApplyQueryChanges(new Dictionary<string, object?> { [name] = current ? null : true, ["page"] = null });

    /// <summary>Sets a filter query parameter, or clears it when null, and resets to page 1.</summary>
    protected void SetFilter(string name, string? value) =>
        ApplyQueryChanges(new Dictionary<string, object?> { [name] = value, ["page"] = null });

    /// <summary>
    /// Applies a sort key from the list's sort picker and resets to page 1, through the URL like every other list state change.
    /// "" is the newest-first default, which keeps a redundant parameter out of the URL.
    /// </summary>
    protected void SetSort(string value) =>
        ApplyQueryChanges(new Dictionary<string, object?> { ["sort"] = string.IsNullOrEmpty(value) ? null : value, ["page"] = null });

    /// <summary>
    /// Adopts a new view reported by the <see cref="ListViewToggle"/>, which persists it to the shared <see cref="ViewPreference"/> and localStorage.
    /// A presentation change over the loaded page, it re-renders in place with no navigation or refetch.
    /// </summary>
    protected void SetView(string value) => _view = value;

    /// <summary>
    /// Navigates to the current list URL with the given query-parameter changes applied (a null value removes the parameter).
    /// The reload happens in <see cref="OnParametersSetAsync"/> once the router supplies the new values, never here, so a button click and browser back or forward take the same path.
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
    /// Matching runs on the server as a detached background task, which can't be awaited there: it chains provider calls, and a slow or dead provider would hold up a create for the resilience timeout, or a bulk import for that timeout per item.
    /// Waiting on the client keeps the create fast and reliable, and puts the delay where it can be bounded and shown.
    /// </para>
    /// <para>
    /// Without the wait the detail page opens unmatched, and the cover, rating and synopsis appear a second or two later, or not, depending on the provider.
    /// A short, predictable wait with a spinner beats a result popping in at an unpredictable moment (owner's call), and removes the window where editing a field could race the match.
    /// </para>
    /// <para>
    /// It gives up quietly, since the item exists either way, most items have no match, and the detail page's own watcher picks up a late arrival.
    /// Only the five reference-linked types wait, and everything else navigates immediately.
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
    /// With <see cref="MatchPollInterval"/>, how long the Add form waits for a match before opening the detail page anyway: two seconds, and never more.
    /// </summary>
    /// <remarks>
    /// It bounds how long a person looks at a spinner rather than estimating how long matching takes, so it follows what is tolerable, not what the provider needs.
    /// A resolve not landed in two seconds finishes on its own, and the detail page's watcher shows it when it arrives.
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
