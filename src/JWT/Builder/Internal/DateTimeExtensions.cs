using System;
using System.Globalization;

namespace JWT.Builder.Internal
{
    internal static class DateTimeExtensions
    {
        public static double GetSecondsSinceEpoch(this DateTime time) => Math.Round((time - JwtValidator.UnixEpoch).TotalSeconds);

        public static string GetSecondsSinceEpochAsString(this DateTime time) => GetSecondsSinceEpoch(time).ToString(CultureInfo.InvariantCulture);
    }
}