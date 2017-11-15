using System;
using System.Collections.Generic;
namespace JWT.JWTBuilder.Models
{
    /// <summary>
    /// Represents the Data that will store in a JWT.
    /// </summary>
    public class JwtData
    {
        /// <summary>
        /// Creates a new instance of <see cref="JwtData" /> and initalizes Header and Payload.
        /// </summary>
        public JwtData()
            : this(new Dictionary<string, string>(), new Dictionary<string, object>())
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="JwtData" />
        /// </summary>
        /// <param name="header">Dictionary that contains the headers</param>
        /// <param name="payload">Dictionary that contans the payload</param>
        public JwtData(IDictionary<string, string> header, IDictionary<string, object> payload)
        {
            this.Header = header;
            this.Payload = payload;
        }

        public JwtData(string token)
        {
            var partsOfToken = token.Split('.');
            if (partsOfToken.Length != 3)
            {
                throw new ArgumentOutOfRangeException(nameof(partsOfToken), "Token must consist of 3 delimited by dot parts.");
            }

        }

        /// <summary>
        /// The header information as a key-value store of the JWT
        /// </summary>
        public IDictionary<string, string> Header { get; set; }

        /// <summary>
        /// The payload of the JWT as a key-value store
        /// </summary>
        public IDictionary<string, object> Payload { get; set; }
    }
}