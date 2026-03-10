using KeepTrack.Common.System;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

namespace KeepTrack.BlazorApp.Components.Inventory;

public abstract class InventoryPageBase<TDto> : ComponentBase
    where TDto : IHasId, new()
{
    [Inject] protected NavigationManager Nav { get; set; } = null!;

    protected abstract InventoryApiClientBase<TDto> Api { get; }

    protected const int PageSize = 20;
    protected List<TDto> Items = [];
    protected TDto Form = new();
    protected TDto? EditingInline;
    protected TDto InlineForm = new();
    protected bool ShowForm;
    protected bool Loading = true;
    protected string? Error;
    protected string Search = "";
    protected int Page = 1;
    protected long TotalCount;
    protected int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);

    protected abstract TDto CloneItem(TDto item);

    protected override async Task OnInitializedAsync() => await LoadAsync();

    protected void OnSearchChanged(string value) => Search = value;

    protected async Task OnSearchKeyUp(KeyboardEventArgs e)
    {
        if (e.Key == "Enter")
        {
            Page = 1;
            await LoadAsync();
        }
    }

    protected async Task ClearSearch()
    {
        Search = "";
        Page = 1;
        await LoadAsync();
    }

    protected async Task GoToPage(int page)
    {
        Page = page;
        await LoadAsync();
    }

    protected void ShowAddForm()
    {
        Form = new TDto();
        ShowForm = true;
        EditingInline = default;
    }

    protected void CancelForm()
    {
        ShowForm = false;
        Error = null;
    }

    protected async Task SaveAsync()
    {
        try
        {
            if (Form.Id is null) await Api.AddAsync(Form);
            else await Api.UpdateAsync(Form);
            ShowForm = false;
            await LoadAsync();
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }
    }

    protected void StartInlineEdit(TDto item)
    {
        ShowForm = false;
        EditingInline = item;
        InlineForm = CloneItem(item);
    }

    protected void CancelInline()
    {
        EditingInline = default;
        Error = null;
    }

    protected async Task SaveInlineAsync()
    {
        try
        {
            await Api.UpdateAsync(InlineForm);
            EditingInline = default;
            await LoadAsync();
        }
        catch (Exception ex)
        {
            Error = ex.Message;
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
            Error = ex.Message;
        }
    }

    private async Task LoadAsync()
    {
        try
        {
            Loading = true;
            var result = await Api.GetAsync(Search, Page, PageSize);
            Items = result.Items;
            TotalCount = result.TotalCount;
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }
        finally
        {
            Loading = false;
        }
    }
}
