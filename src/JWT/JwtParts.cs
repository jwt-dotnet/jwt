using System;

namespace JWT
{
    /// <summary>
    /// Represent the parts of a JWT
    /// </summary>
    public class JwtParts
    {
        /// <summary>
        /// Creates a new instance of <see cref="JwtParts" /> from the string representation of a JWT
        /// </summary>
        /// <param name="token">The string representation of a JWT.</param>
        public JwtParts(string token)
            : this(SplitToken(token))
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="JwtParts" /> from the array representation of a JWT
        /// </summary>
        /// <param name="parts">The array representation of a JWT.</param>
        public JwtParts(string[] parts) => this.Parts = parts;

        /// <summary>
        /// Gets the Header part of a JWT
        /// </summary>
        public string Header => this.Parts[(int)JwtPartsIndex.Header];

        /// <summary>
        ///  Gets the Payload part of a JWT
        /// </summary>
        public string Payload => this.Parts[(int)JwtPartsIndex.Payload];

        /// <summary>
        /// Gets the Signature part of a JWT
        /// </summary>
        public string Signature => this.Parts[(int)JwtPartsIndex.Signature];

        /// <summary>
        /// Gets the parts of a JWT
        /// </summary>
        public string[] Parts { get; }

        /// <summary>
        /// Splits the string representation of a JWT in to its parts
        /// </summary>
        private static string[] SplitToken(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }
            return parts;

        }

        /// <summary>
        /// Helper enum to get the correct part from the array representation of a JWT parts
        /// </summary>
        private enum JwtPartsIndex
        {
            Header = 0,
            Payload = 1,
            Signature = 2
        }
    }
}