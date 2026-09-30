using System.IO;
using System.Text;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

internal static class CsvTestHelper
{
    public static Stream ToStream(string csv) => new MemoryStream(Encoding.UTF8.GetBytes(csv));
}
