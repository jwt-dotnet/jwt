using System.ComponentModel;
using System.Reflection;
using JWT.JWTBuilder.Enums;

namespace JWT.JwtBuilder.Helpers
{
    internal static class EnumHelper
    {
        /// <summary>
        /// Get the Header-Name from the enum-value
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string GetHeaderName(this HeaderName value) => GetValueOfDescription(value);

        /// <summary>
        /// Gets the ClaimName from the enum-value
        /// </summary>
        /// <param name="value">The <see cref="PublicClaimsNames" /> you want the describtion</param>
        /// <returns>The string to the enum value</returns>
        public static string GetPublicClaimName(this PublicClaimsNames value) => GetValueOfDescription(value);

        /// <summary>
        /// Gets the Value of the Describtion Attribut from a object.
        /// </summary>
        /// <param name="value">A object that have the Describtion Attribut set</param>
        /// <returns>The string of the Describtion</returns>
        private static string GetValueOfDescription(object value)
        {
            var info = value.GetType().GetField(value.ToString());
            var attribute = info.GetCustomAttribute<DescriptionAttribute>();
            return attribute != null ? attribute.Description : value.ToString();
        }
    }
}