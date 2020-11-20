using System;

namespace JWT.Tests.Stubs
{
    public sealed class StaticDateTimeProvider : IDateTimeProvider
    {
        private readonly DateTimeOffset _now;

        public StaticDateTimeProvider(DateTimeOffset now)
        {
            _now = now;
        }

        public DateTimeOffset GetNow()
        {
            return _now;
        }
    }
}
