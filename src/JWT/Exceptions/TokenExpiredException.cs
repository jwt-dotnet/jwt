using System;
using System.Collections.Generic;

#if NET35 || NET40
using IReadOnlyPayloadDictionary = System.Collections.Generic.IDictionary<string, object>;
#else
using IReadOnlyPayloadDictionary = System.Collections.Generic.IReadOnlyDictionary<string, object>;
#endif

namespace JWT.Exceptions
{
    /// <summary>
    /// Represents an exception thrown when when a token is expired.
    /// </summary>
    public class TokenExpiredException : SignatureVerificationException
    {
        private const string PayloadDataKey = "PayloadData";
        private const string ExpirationKey = "Expiration";

        /// <summary>
        /// Creates an instance of <see cref="TokenExpiredException" />
        /// </summary>
        /// <param name="message">The error message</param>
        public TokenExpiredException(string message)
             : base(message)
        {
        }

        /// <summary>
        /// The payload.
        /// </summary>
        public IReadOnlyPayloadDictionary PayloadData
        {
            get => GetOrDefault<Dictionary<string, object>>(PayloadDataKey);
            internal set => this.Data.Add(PayloadDataKey, value);
        }

        /// <summary>
        /// The expiration DateTime of the token.
        /// </summary>
        public DateTime? Expiration
        {
            get => GetOrDefault<DateTime?>(ExpirationKey);
            internal set => this.Data.Add(ExpirationKey, value);
        }
    }
}