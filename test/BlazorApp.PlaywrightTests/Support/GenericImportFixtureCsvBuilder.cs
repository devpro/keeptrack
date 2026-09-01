using System;
using System.Text;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a minimal one-row generic store/CSV import fixture for the import smoke test, using the real-world
/// Rakuten header shape. The row carries an explicit "Type" column (Book) so it's auto-selected without relying
/// on any heuristic, plus a per-call unique title and fresh order id so every run imports a genuinely new book
/// the test then deletes - never a dedup-hidden "already imported" row from a previous run.
/// Never use a real personal export as a fixture (same rule as the integration suite's own builders).
/// </summary>
internal static class GenericImportFixtureCsvBuilder
{
    public static byte[] Build(string bookTitle)
    {
        var orderId = $"GEN-{Guid.NewGuid():N}";
        var csv = $"""
                   Order Date,Order ID,ASIN,Product Name,Product Condition,Total Amount,Vendor,Type,Platform,Author
                   2024-01-24,{orderId},GEN-ASIN-1,{bookTitle},New,10.49,Rakuten,Book,,E2e Test Author

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
