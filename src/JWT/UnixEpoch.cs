using System;
using System.Globalization;

namespace JWT
{
    public static class UnixEpoch
    {
        /// <summary>
        /// Describes a point in time, defined as the number of seconds that have elapsed since 00:00:00 UTC, Thursday, 1 January 1970, not counting leap seconds.
        /// See https://en.wikipedia.org/wiki/Unix_time />
        /// </summary>
        public static DateTime Value { get; } = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public static double GetSecondsSince(DateTimeOffset time) =>
            Math.Round((time - Value).TotalSeconds);
    }
}
