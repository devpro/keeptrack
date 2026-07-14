using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Houses : InventoryPageBase<HouseDto>
{
    [Inject] private HouseApiClient HouseApi { get; set; } = null!;

    [Inject] private NavigationManager Nav { get; set; } = null!;

    protected override InventoryApiClientBase<HouseDto> Api => HouseApi;

    /// <summary>
    /// Creating a house only ever captures identity fields here (see <c>FormTemplate</c>) - notes and history
    /// are added on the detail page, so a successful create navigates straight there instead of closing the
    /// form and staying on the list (same as <c>Cars.razor.cs</c>'s <c>SaveAsync</c>).
    /// </summary>
    protected override async Task SaveAsync()
    {
        try
        {
            if (_form.Id is null)
            {
                var created = await HouseApi.AddAsync(_form);
                _showForm = false;
                Nav.NavigateTo($"/houses/{created.Id}");
            }
            else
            {
                await HouseApi.UpdateAsync(_form);
                _showForm = false;
                await LoadAsync();
            }
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

    protected override HouseDto CloneItem(HouseDto item) => new()
    {
        Id = item.Id,
        Name = item.Name,
        Address = item.Address,
        City = item.City,
        PostalCode = item.PostalCode,
        Country = item.Country,
        Notes = item.Notes
    };
}
