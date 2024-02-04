using System;

namespace JWT.Exceptions
{
    public class InvalidJsonWebKeyTypeException : ArgumentOutOfRangeException
    {
        public InvalidJsonWebKeyTypeException(string keyType)
            : base($"{keyType} is not defined in RFC7518")
        {
            
        }
    }
}