using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Books : InventoryPageBase<BookDto>
{
    [Inject] private BookApiClient BookApi { get; set; } = null!;

    protected override InventoryApiClientBase<BookDto> Api => BookApi;

    protected override string ListRoute => "/books";

    [SupplyParameterFromQuery(Name = "favorite")]
    public bool FavoriteFilter { get; set; }

    [SupplyParameterFromQuery(Name = "owned")]
    public bool OwnedFilter { get; set; }

    [SupplyParameterFromQuery(Name = "unread")]
    public bool UnreadFilter { get; set; }

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (FavoriteFilter) query["IsFavorite"] = "true";
            if (OwnedFilter) query["IsOwned"] = "true";
            if (UnreadFilter) query["IsUnread"] = "true";
            return query.Count > 0 ? query : null;
        }
    }
}
