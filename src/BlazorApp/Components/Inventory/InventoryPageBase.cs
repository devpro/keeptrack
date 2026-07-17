using Keeptrack.Common.System;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

namespace Keeptrack.BlazorApp.Components.Inventory;

public abstract class InventoryPageBase<TDto> : ComponentBase
    where TDto : IHasId, new()
{
    private const int PageSize = 20;

    protected List<TDto> _items = [];

    protected TDto _form = new();

    protected bool _showForm;

    protected bool _loading = true;

    protected string? _error;

    protected string _search = "";

    protected string _sort = "";

    protected int _page = 1;

    protected long _totalCount;

    private string? _loadedQuery;

    protected int TotalPages => (int)Math.Ceiling(_totalCount / (double)PageSize);

    [Inject] protected NavigationManager Navigation { get; set; } = null!;

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
    /// Runs on the initial load and again whenever the router supplies new query-parameter values
    /// (a filter/page click's NavigateTo, but also browser back/forward), so every way of changing
    /// list state goes through this single reload path. The signature check keeps unrelated
    /// parameter updates (e.g. a cascading auth-state refresh) from re-fetching the same query.
    /// </summary>
    protected override async Task OnParametersSetAsync()
    {
        _search = SearchQuery ?? "";
        _sort = SortQuery ?? "";
        _page = PageQuery is > 0 ? PageQuery.Value : 1;
        var query = BuildQuerySignature();
        if (query != _loadedQuery)
        {
            _loadedQuery = query;
            await LoadAsync();
        }
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
            Navigation.NavigateTo($"{ListRoute}/{created.Id}");
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

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
            _loading = true;
            var result = await Api.GetAsync(_search, _page, PageSize, ExtraQuery, _sort);
            _items = result.Items;
            _totalCount = result.TotalCount;
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
        finally
        {
            _loading = false;
        }
    }

    private string BuildQuerySignature()
    {
        var extra = ExtraQuery is null ? "" : string.Join('&', ExtraQuery.Select(pair => $"{pair.Key}={pair.Value}"));
        return $"{_search}|{_page}|{_sort}|{extra}";
    }
}
