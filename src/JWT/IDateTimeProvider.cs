using System;

namespace JWT
{
    /// <summary>
    /// DateTimeProvider interface.
    /// </summary>
    public interface IDateTimeProvider
    {

        /// <summary>
        /// Get the current DateTime.
        /// </summary>
        /// <returns></returns>
        DateTime GetNow();
    }
}