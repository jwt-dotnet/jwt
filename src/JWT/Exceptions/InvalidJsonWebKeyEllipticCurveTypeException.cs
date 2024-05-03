using System;

namespace JWT.Exceptions
{
    public class InvalidJsonWebKeyEllipticCurveTypeException : ArgumentOutOfRangeException
    {
        public InvalidJsonWebKeyEllipticCurveTypeException(string ellipticCurveType)
            : base($"{ellipticCurveType} is not defined in RFC751")
        {
        }
    }
}