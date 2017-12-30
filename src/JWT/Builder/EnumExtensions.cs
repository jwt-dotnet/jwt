using System.ComponentModel;
using System.Reflection;

namespace JWT.Builder
{
    internal static class EnumExtensions
    {
        /// <summary>
        /// Gets the string representation of a well-known header name enum
        /// </summary>
        public static string GetHeaderName(this HeaderName value) => GetDescription(value);

        /// <summary>
        /// Gets the string representation of a well-known claim name enum
        /// </summary>
        public static string GetPublicClaimName(this ClaimName value) => GetDescription(value);

        /// <summary>
        /// Gets the value of the Describtion Attribute from the object.
        /// </summary>
        /// <param name="value">An object that is decorated with <see cref="DescriptionAttribute"/></param>
        private static string GetDescription(object value) => value.GetType()
                                                                   .GetField(value.ToString())
                                                                   .GetCustomAttribute<DescriptionAttribute>()?.Description ?? value.ToString();
    }
}