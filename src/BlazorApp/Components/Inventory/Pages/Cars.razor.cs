using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Cars : InventoryPageBase<CarDto>
{
    [Inject] private CarApiClient CarApi { get; set; } = null!;

    [Inject] private NavigationManager Nav { get; set; } = null!;

    protected override InventoryApiClientBase<CarDto> Api => CarApi;

    /// <summary>
    /// Creating a car only ever captures identity fields here (see <c>FormTemplate</c>) - energy type and
    /// history are added on the detail page, so a successful create navigates straight there instead of
    /// closing the form and staying on the list (same as <c>VideoGames.razor.cs</c>'s <c>SaveAsync</c>).
    /// </summary>
    protected override async Task SaveAsync()
    {
        try
        {
            if (_form.Id is null)
            {
                var created = await CarApi.AddAsync(_form);
                _showForm = false;
                Nav.NavigateTo($"/cars/{created.Id}");
            }
            else
            {
                await CarApi.UpdateAsync(_form);
                _showForm = false;
                await LoadAsync();
            }
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

    protected override CarDto CloneItem(CarDto item) => new()
    {
        Id = item.Id,
        Name = item.Name,
        Manufacturer = item.Manufacturer,
        Model = item.Model,
        Year = item.Year,
        LicensePlate = item.LicensePlate,
        EnergyType = item.EnergyType
    };
}
