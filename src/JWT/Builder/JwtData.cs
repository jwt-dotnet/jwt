using System;
using System.Collections.Generic;

namespace JWT.Builder
{
    /// <summary>
    /// Represents the Data that will store in a JWT.
    /// </summary>
    public class JwtData
    {
        /// <summary>
        /// Creates a new instance of <see cref="JwtData" /> with empty Header and Payload.
        /// </summary>
        public JwtData()
            : this(null, null)
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="JwtData" />
        /// </summary>
        /// <param name="payload">Dictionary that contans the payload</param>
        public JwtData(IDictionary<string, object> payload)
        : this(null, payload)
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="JwtData" />
        /// </summary>
        /// <param name="header">Dictionary that contains the headers</param>
        /// <param name="payload">Dictionary that contans the payload</param>
        public JwtData(IDictionary<string, object> header, IDictionary<string, object> payload)
        {
            this.Header = header ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            this.Payload = payload ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Creates a new instance of <see cref="JwtData" />
        /// </summary>
        /// <param name="token">The JWT token</param>
        public JwtData(string token)
        {
            var partsOfToken = token.Split('.');
            if (partsOfToken.Length != 3)
                throw new InvalidTokenPartsException(nameof(token));
        }

        /// <summary>
        /// The header information as a key-value store of the JWT
        /// </summary>
        public IDictionary<string, object> Header { get; }

        /// <summary>
        /// The payload of the JWT as a key-value store
        /// </summary>
        public IDictionary<string, object> Payload { get; }
    }
}