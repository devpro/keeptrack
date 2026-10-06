using System;
using System.Text;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a minimal one-row generic store CSV fixture for the import smoke test, with the real Rakuten header shape.
/// The row's explicit "Type" column (Book) selects it without a heuristic, and a per-call unique title and fresh order id make every run import a new book the test deletes.
/// A real personal export is never a fixture, as in the integration suite's builders.
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
