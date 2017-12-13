using System.ComponentModel;
using System.Reflection;

namespace JWT.Builder.Internal
{
    internal static class EnumHelper
    {
        /// <summary>
        /// Get the HeaderName from the enum-value
        /// </summary>
        public static string GetHeaderName(this HeaderName value) => GetDescription(value);

        /// <summary>
        /// Get the ClaimName from the enum-value
        /// </summary>
        public static string GetPublicClaimName(this ClaimName value) => GetDescription(value);

        /// <summary>
        /// Get the Value of the Describtion Attribut from a object.
        /// </summary>
        /// <param name="value">An object that is decorated with <see cref="DescriptionAttribute"/></param>
        private static string GetDescription(object value)
        {
            var info = value.GetType().GetField(value.ToString());
            return info.GetCustomAttribute<DescriptionAttribute>()?.Description ?? value.ToString();
        }
    }
}