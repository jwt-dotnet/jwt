using System.Text;

namespace JWT.Internal
{
    internal static class EncodingHelper
    {
        private static readonly UTF8Encoding utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public static byte[] GetBytes(string input) =>
            utf8Encoding.GetBytes(input);

        public static byte[] GetBytes(string input1, byte separator, string input2)
        {
            byte[] output = new byte[utf8Encoding.GetByteCount(input1) + utf8Encoding.GetByteCount(input2) + 1];
            int bytesWritten = utf8Encoding.GetBytes(input1, 0, input1.Length, output, 0);
            output[bytesWritten++] = separator;
            utf8Encoding.GetBytes(input2, 0, input2.Length, output, bytesWritten);
            return output;
        }

        public static byte[][] GetBytes(string[] input)
        {
            byte[][] results = new byte[input.Length][];
            for (int i = 0; i < input.Length; i++)
            {
                results[i] = GetBytes(input[i]);
            }
            return results;
        }

        public static string GetString(byte[] bytes) =>
            utf8Encoding.GetString(bytes);
    }
}