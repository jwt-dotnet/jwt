namespace JWT.Internal
{
    internal static class StringHelper
    {
        internal static string FirstSegment(this string input, char separator)
        {
            int idx = input.IndexOf(separator);
            if (idx != -1)
            {
                return input.Substring(0, idx);
            }
            return input;
        }

        internal static int Count(this string input, char character)
        {
            int counter = 0;
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
