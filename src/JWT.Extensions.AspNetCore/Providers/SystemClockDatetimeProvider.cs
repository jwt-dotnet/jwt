using System;
using Microsoft.AspNetCore.Authentication;

namespace JWT.Providers
{
    public sealed class SystemClockDatetimeProvider : IDateTimeProvider
    {
        private readonly ISystemClock _clock;

        public SystemClockDatetimeProvider(ISystemClock clock) =>
            _clock = clock;

        public DateTimeOffset GetNow() =>
            _clock.UtcNow;
    }
}