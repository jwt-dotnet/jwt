using System;

namespace JWT.Internal
{
    internal sealed class UtcDatetimeProvider : IDateTimeProvider
    {
        public DateTimeOffset GetNow() =>
            DateTimeOffset.UtcNow;
    }
}