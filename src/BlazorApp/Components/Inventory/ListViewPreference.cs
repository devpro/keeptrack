namespace Keeptrack.BlazorApp.Components.Inventory;

/// <summary>
/// Circuit-scoped holder for the user's view preference ("" for the detailed list, "grid" for poster thumbnails).
/// Registered scoped, it lives for one Blazor Server circuit and is shared by every list page, so flipping the view on one carries to the others for the session.
///
/// It is seeded once per circuit from localStorage (see ListViewToggle), so the choice survives a full reload and later sessions.
/// The prerender can't read localStorage, so this in-memory holder carries the choice across in-circuit navigations rather than re-reading storage, and re-flashing, on every page.
/// </summary>
public sealed class ListViewPreference
{
    /// <summary>The localStorage key the preference is persisted under.</summary>
    public const string StorageKey = "kt-list-view";

    /// <summary>Whether this circuit has already read the persisted value once (see the class summary).</summary>
    public bool Seeded { get; set; }

    /// <summary>Current view: "" for the detailed list (default) or "grid" for poster thumbnails.</summary>
    public string View { get; set; } = "";
}
