using System;

namespace JWT
{
    public sealed class UtcDateTimeProvider : IDateTimeProvider
    {
        public DateTime GetNow()
        {
            return DateTime.UtcNow;
        }
    }
}