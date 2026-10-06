using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Gear has no reference data, like <see cref="CarDetailPage"/>, so a plain <see cref="DetailPageBase"/>.
/// </summary>
public class GearDetailPage(IPage page) : DetailPageBase(page);
