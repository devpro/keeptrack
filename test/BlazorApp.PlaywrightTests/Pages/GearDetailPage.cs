using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Gear has no reference-data concept, same as <see cref="CarDetailPage"/> - a plain <see cref="DetailPageBase"/>.
/// </summary>
public class GearDetailPage(IPage page) : DetailPageBase(page);
