using System;

namespace JWT.Exceptions
{
    public class SignatureVerificationException : Exception
    {
        public SignatureVerificationException(string message)
            : base(message)
        {
        }
    }
}