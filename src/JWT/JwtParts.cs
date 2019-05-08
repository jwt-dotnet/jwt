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
        /// <param name="token">The string representation of a JWT</param>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public JwtParts(string token)
        {
            if (String.IsNullOrWhiteSpace(token))
                throw new ArgumentException(nameof(token));

            var parts = token.Split('.');
            if (parts.Length != 3)
                throw new InvalidTokenPartsException(nameof(token));

            this.Parts = parts;
        }

        /// <summary>
        /// Creates a new instance of <see cref="JwtParts" /> from the array representation of a JWT
        /// </summary>
        /// <param name="parts">The array representation of a JWT</param>
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public JwtParts(string[] parts)
        {
            if (parts is null)
                throw new ArgumentNullException(nameof(parts));
            if (parts.Length != 3)
                throw new InvalidTokenPartsException(nameof(parts));

            this.Parts = parts;
        }

        /// <summary>
        /// Gets the Header part of a JWT
        /// </summary>
        public string Header =>
            this.Parts[(int)JwtPartsIndex.Header];

        /// <summary>
        /// Gets the Payload part of a JWT
        /// </summary>
        public string Payload =>
            this.Parts[(int)JwtPartsIndex.Payload];

        /// <summary>
        /// Gets the Signature part of a JWT
        /// </summary>
        public string Signature =>
            this.Parts[(int)JwtPartsIndex.Signature];

        /// <summary>
        /// Gets the parts of a JWT
        /// </summary>
        public string[] Parts { get; }

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