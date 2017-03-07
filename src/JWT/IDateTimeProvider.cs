using System;

namespace JWT
{
    public interface IDateTimeProvider
    {
        DateTime GetNow();
    }
}