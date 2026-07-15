using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Playlists have no reference-data concept at all (confirmed: no <c>ReferenceId</c> on <c>PlaylistDto</c>,
/// no <c>InlineReferenceLinker</c> in <c>PlaylistDetail.razor</c>), so this is a plain <see cref="DetailPageBase"/>.
/// </summary>
public class PlaylistDetailPage(IPage page) : DetailPageBase(page);
