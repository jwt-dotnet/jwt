using System;

namespace JWT
{
    /// <summary>
    /// Represents a DateTime provider.
    /// </summary>
    public interface IDateTimeProvider
    {
        /// <summary>
        /// Gets the current DateTime.
        /// </summary>
        DateTimeOffset GetNow();
    }
}