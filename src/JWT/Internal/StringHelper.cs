namespace JWT.Internal
{
    internal static class StringHelper
    {
        public static bool IsNullOrWhiteSpace(string value)
        {
#if NET35
            if (!string.IsNullOrEmpty(value))
            {
                foreach (var ch in value)
                {
                    if (!char.IsWhiteSpace(ch)) return false;
                }
            }
            return true;
#else
            return string.IsNullOrWhiteSpace(value);
#endif
        }
    }
}
