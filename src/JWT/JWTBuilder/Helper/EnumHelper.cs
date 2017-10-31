using System.ComponentModel;
using JWT.JWTBuilder.Enums;

namespace JWT.JWTBuilder.Helper
{
    public static class EnumHelper
    {
        /// <summary>
        /// Get the Header-Name from the enum-value
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string GetHeaderName(this HeaderNames value) => getValueOfDescription(value);

        /// <summary>
        /// Get the ClaimName from the enum-value
        /// </summary>
        /// <param name="value">The <see cref="PublicClaimsNames" you want the describtion/></param>
        /// <returns>The string to the enum value</returns>
        public static string GetPublicClaimName(this PublicClaimsNames value) => getValueOfDescription(value);

        /// <summary>
        /// Get the Value of the Describtion Attribut from a object.
        /// </summary>
        /// <param name="value">A object that have the Describtion Attribut set</param>
        /// <returns>The string of the Describtion</returns>
        private static string getValueOfDescription(object value)
        {
            var info = value.GetType().GetField(value.ToString());
            var attributes = (DescriptionAttribute[])info.GetCustomAttributes(typeof(DescriptionAttribute), false);
            if (attributes != null && attributes.Length > 0)
            {
                return attributes[0].Description;
            }
            else
            {
                return value.ToString();
            }
        }
    }
}