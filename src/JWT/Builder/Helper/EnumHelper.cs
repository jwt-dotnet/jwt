using System.ComponentModel;
using System.Reflection;
using JWT.Builder.Enums;

namespace JWT.Builder.Helper
{
    public static class EnumHelper
    {
        /// <summary>
        /// Get the Header-Name from the enum-value
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string GetHeaderName(this HeaderName value) => GetValueOfDescription(value);

        /// <summary>
        /// Get the ClaimName from the enum-value
        /// </summary>
        /// <param name="value">The <see cref="PublicClaimsNames" you want the describtion/></param>
        /// <returns>The string to the enum value</returns>
        public static string GetPublicClaimName(this PublicClaimsNames value) => GetValueOfDescription(value);

        /// <summary>
        /// Get the Value of the Describtion Attribut from a object.
        /// </summary>
        /// <param name="value">A object that have the Describtion Attribut set</param>
        /// <returns>The string of the Describtion</returns>
        private static string GetValueOfDescription(object value)
        {
            var info = value.GetType().GetField(value.ToString());
            var attribute = info.GetCustomAttribute<DescriptionAttribute>();
            if (attribute != null)
            {
                return attribute.Description;
            }
            else
            {
                return value.ToString();
            }
        }
    }
}