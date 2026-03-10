using KeepTrack.Common.System;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

namespace KeepTrack.BlazorApp.Components.Inventory;

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

    protected abstract InventoryApiClientBase<TDto> Api { get; }

    protected abstract TDto CloneItem(TDto item);

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

    protected async Task SaveAsync()
    {
        try
        {
            if (_form.Id is null) await Api.AddAsync(_form);
            else await Api.UpdateAsync(_form);
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

    private async Task LoadAsync()
    {
        try
        {
            _loading = true;
            var result = await Api.GetAsync(_search, _page, PageSize);
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
