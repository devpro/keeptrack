namespace Keeptrack.BlazorApp.Components.Inventory;

/// <summary>
/// Circuit-scoped holder for the user's list/thumbnail view preference ("" = detailed list, "grid" =
/// poster thumbnails). Registered scoped, so it lives for the lifetime of one Blazor Server circuit and is
/// shared by every <see cref="InventoryPageBase{TDto}"/> - flipping the view on one list page carries to
/// every other list page for the session without re-clicking the toggle.
///
/// It is seeded once per circuit from the browser's localStorage (see InventoryPageBase.OnAfterRenderAsync)
/// so the choice also survives a full reload and future sessions. localStorage can't be read during the
/// server-side prerender, which is why an in-memory holder carries it across in-circuit navigations instead
/// of re-reading storage (and re-flashing) on every page.
/// </summary>
public sealed class ListViewPreference
{
    /// <summary>The localStorage key the preference is persisted under.</summary>
    public const string StorageKey = "kt-list-view";

    /// <summary>Whether this circuit has already read the persisted value once (see the class summary).</summary>
    public bool Seeded { get; set; }

    /// <summary>Current view: "" (detailed list, the default) or "grid" (poster thumbnails).</summary>
    public string View { get; set; } = "";
}
