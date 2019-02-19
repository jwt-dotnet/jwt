using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JWT.Internal
{
    internal static class EncodingHelper
    {
        internal static byte[] GetBytes(string input) =>
            Encoding.UTF8.GetBytes(input);

        internal static byte[][] GetBytes(IEnumerable<string> input) =>
            input.Select(GetBytes).ToArray();

        internal static string GetString(byte[] bytes) =>
            Encoding.UTF8.GetString(bytes);
    }
}