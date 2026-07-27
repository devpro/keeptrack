using System;
using System.Text;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a minimal one-row video-game transaction-history CSV (PSN-style export shape) for the import smoke test.
/// The single row carries a per-call unique title plus a fresh transaction/order id so every run imports a genuinely new game the test then deletes,
/// and a real platform value (<c>PS4</c>) so the preview's platform column is pre-filled and the commit button enables without further input.
/// Never use a real personal export as a fixture (same rule as the integration suite's own builders).
/// </summary>
internal static class GenericVideoGameImportFixtureCsvBuilder
{
    public static byte[] Build(string gameTitle)
    {
        var transactionId = Guid.NewGuid().ToString("N");
        var orderId = Guid.NewGuid().ToString("N");
        var csv = $"""
                   Transaction Date,Game Name,Product Name,Platform,Vendor,Transaction Id,Order Id,Final Price (€)
                   2019-08-02,{gameTitle},{gameTitle},PS4,PlayStation Store,{transactionId},{orderId},14.99

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
