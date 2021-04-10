#if NET35
namespace JWT.Compatibility
{
    internal static class String
    {
        public static bool IsNullOrWhiteSpace(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                foreach (var ch in value)
                {
                    if (!char.IsWhiteSpace(ch))
                        return false;
                }
            }
            return true;
        }
    }
}
#endif
