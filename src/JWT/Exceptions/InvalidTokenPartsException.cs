using System;

namespace JWT.Exceptions
{
    /// <summary>
    /// Represents an exception thrown when a token doesn't consist of 3 delimited by dot parts.
    /// </summary>
    public class InvalidTokenPartsException : ArgumentOutOfRangeException
    {
        /// <summary>
        /// Creates an instance of <see cref="InvalidTokenPartsException" />
        /// </summary>
        /// <param name="paramName">The name of the parameter that caused the exception</param>
        public InvalidTokenPartsException(string paramName)
            : base(paramName, "Token must consist of 3 delimited by dot parts.")
        {
        }
    }
}
