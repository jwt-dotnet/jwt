﻿using System;

namespace JWT
{
    /// <summary>
    /// Represents an exception thrown when when a token doesn't consist of 3 delimited by dot parts.
    /// </summary>
    public class InvalidTokenPartsException : ArgumentOutOfRangeException
    {
        /// <summary>
        /// Create the SignatureVerificationException.
        /// </summary>
        /// <param name="paramName">The name of the parameter that caused the exception.</param>
        public InvalidTokenPartsException(string paramName)
            : base(paramName, "Token must consist of 3 delimited by dot parts.")
        {
        }
    }
}