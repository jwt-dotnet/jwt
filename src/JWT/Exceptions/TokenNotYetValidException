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
    /// Represents an exception thrown when a token is not yet valid.
    /// </summary>
    public class TokenNotYetValidException : SignatureVerificationException
    {
        private const string PayloadDataKey = "PayloadData";
        private const string NotBeforeKey = "NotBefore";

        /// <summary>
        /// Creates an instance of <see cref="TokenNotYetValidException" />
        /// </summary>
        /// <param name="message">The error message</param>
        public TokenNotYetValidException(string message)
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
        /// The not before DateTime of the token.
        /// </summary>
        public DateTime? NotBefore
        {
            get => GetOrDefault<DateTime?>(NotBeforeKey);
            internal set => this.Data.Add(NotBeforeKey, value);
        }
    }
}
