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

    protected TDto? _editingInline;

    protected TDto _inlineForm = new();

    protected bool _showForm;

    protected bool _loading = true;

    protected string? _error;

    protected string _search = "";

    protected int _page = 1;

    protected long _totalCount;

    protected int TotalPages => (int)Math.Ceiling(_totalCount / (double)PageSize);

    [Inject] protected NavigationManager Navigation { get; set; } = null!;

    protected abstract InventoryApiClientBase<TDto> Api { get; }

    protected abstract TDto CloneItem(TDto item);

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

    protected override async Task OnInitializedAsync() => await LoadAsync();

    protected void OnSearchChanged(string value) => _search = value;

    protected async Task OnSearchKeyUp(KeyboardEventArgs e)
    {
        if (e.Key == "Enter")
        {
            _page = 1;
            await LoadAsync();
        }
    }

    protected async Task ClearSearch()
    {
        _search = "";
        _page = 1;
        await LoadAsync();
    }

    protected async Task GoToPage(int page)
    {
        _page = page;
        await LoadAsync();
    }

    protected void ShowAddForm()
    {
        _form = new TDto();
        _showForm = true;
        _editingInline = default;
    }

    protected void CancelForm()
    {
        _showForm = false;
        _error = null;
    }

    protected virtual async Task SaveAsync()
    {
        try
        {
            if (_form.Id is null)
            {
                var created = await Api.AddAsync(_form);
                Navigation.NavigateTo($"{ListRoute}/{created.Id}");
                return;
            }
            await Api.UpdateAsync(_form);
            _showForm = false;
            await LoadAsync();
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

    protected void StartInlineEdit(TDto item)
    {
        _showForm = false;
        _editingInline = item;
        _inlineForm = CloneItem(item);
    }

    protected void CancelInline()
    {
        _editingInline = default;
        _error = null;
    }

    protected async Task SaveInlineAsync()
    {
        try
        {
            await Api.UpdateAsync(_inlineForm);
            _editingInline = default;
            await LoadAsync();
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
            var result = await Api.GetAsync(_search, _page, PageSize, ExtraQuery);
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
}
