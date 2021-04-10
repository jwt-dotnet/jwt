using System;

namespace JWT.Compatibility
{
    internal static class String
    {
#if !NETSTANDARD
        /// <remarks>
        /// The overload accpting char is missing outside .NET Standard.
        /// See https://docs.microsoft.com/en-us/dotnet/api/system.string.indexof?view=netstandard-2.0#System_String_IndexOf_System_String_System_StringComparison_
        /// </remarks>
        public static int IndexOf(this string value, char ch, StringComparison comparisonType)
        {
            return value.IndexOf(ch.ToString(), comparisonType);
        }
#endif
  
#if NET35
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
#endif
}
