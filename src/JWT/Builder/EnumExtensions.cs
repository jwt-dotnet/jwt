using System.ComponentModel;
using System.Reflection;

namespace JWT.Builder
{
    internal static class EnumExtensions
    {
        /// <summary>
        /// Gets the string representation of a well-known header name enum
        /// </summary>
        public static string GetHeaderName(this HeaderName value)
        {
            var name = value.ToString();
            return GetDescription(typeof(HeaderName).GetField(name), name);
        }

        /// <summary>
        /// Gets the string representation of a well-known claim name enum
        /// </summary>
        public static string GetPublicClaimName(this ClaimName value)
        {
            var name = value.ToString();
            return GetDescription(typeof(ClaimName).GetField(name), name);
        }

        /// <summary>
        /// Gets the value of the DescriptionAttribute from the enum field.
        /// </summary>
        private static string GetDescription(FieldInfo field, string valueString) =>
            field.GetCustomAttribute<DescriptionAttribute>()
                ?.Description ?? valueString;
    }
}