using System;

namespace JWT.Exceptions
{
    public class JwtFormatException : Exception
    {
        public JwtFormatException(string message) : base(message)
        {
        }

        public JwtFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}