using System.Text;

namespace JWT.Internal
{
    internal static class EncodingHelper
    {
        private static readonly UTF8Encoding _utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public static byte[] GetBytes(string input) =>
            _utf8Encoding.GetBytes(input);

        public static byte[] GetBytes(string input1, char separator, string input2) =>
            GetBytes(input1, (byte)separator, input2);

        public static byte[] GetBytes(string input1, byte separator, string input2)
        {
            byte[] output = new byte[_utf8Encoding.GetByteCount(input1) + _utf8Encoding.GetByteCount(input2) + 1];
            int bytesWritten = _utf8Encoding.GetBytes(input1, 0, input1.Length, output, 0);
            output[bytesWritten++] = separator;
            _utf8Encoding.GetBytes(input2, 0, input2.Length, output, bytesWritten);
            return output;
        }

        public static byte[][] GetBytes(string[] input)
        {
            if (input is null)
                return null;

            byte[][] results = new byte[input.Length][];
            for (int i = 0; i < input.Length; i++)
            {
                results[i] = GetBytes(input[i]);
            }
            return results;
        }

        public static string GetString(byte[] bytes) =>
            _utf8Encoding.GetString(bytes);
    }
}