#if NET35
using System;

namespace JWT.Compatibility
{
    internal static class String
    {
        public static int IndexOf(this string value, char ch, StringComparison comparisonType)
        {
            // ignores comparisonType since the overload is missing in .NET 3.5
            return value.IndexOf(ch);
        }
    
        public static bool IsNullOrWhiteSpace(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                foreach (var ch in value)
                {
                    if (!char.IsWhiteSpace(ch)) return false;
                }
            }
            return true;
        }
    }
}
#endif
