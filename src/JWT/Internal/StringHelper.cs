using System;

namespace JWT.Internal
{
    internal static class StringHelper
    {
        public static string FirstSegment(this string input, char separator)
        {
            var idx = input.IndexOf(separator);
            return idx != -1 ? input.Substring(0, idx): input;
        }

        public static int Count(this string input, char character)
        {
            var counter = 0;
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == character)
                {
                    counter++;
                }
            }
            return counter;
        }
    }
}
