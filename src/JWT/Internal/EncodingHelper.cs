using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JWT.Internal
{
    internal static class EncodingHelper
    {
        internal static byte[] GetBytes(string input) =>
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(input);

        internal static byte[][] GetBytes(IEnumerable<string> input) =>
            input.Select(GetBytes).ToArray();

        internal static string GetString(byte[] bytes) =>
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetString(bytes);
    }
}
