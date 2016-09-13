using System;

namespace JWT
{
    public class TokenExpiredException : Exception
    {
        public TokenExpiredException(string message)
            : base(message)
        {
        }
    }
}