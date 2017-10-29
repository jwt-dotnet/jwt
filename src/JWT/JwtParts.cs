using System;
using System.Linq;

namespace JWT
{
    /// <summary>
    /// A class that represent a JWT
    /// </summary>
    public class JwtParts
    {
        /// <summary>
        /// An array that has length of 3 because the JWT has 3 parts
        /// </summary>
        private readonly string[] _parts;

        /// <summary>
        /// Creates a new Instance of JWT from the string representation of a JWT
        /// </summary>
        /// <param name="token">The JWT as string</param>
        public JwtParts(string token): this(SplitToken(token)) { }

        /// <summary>
        /// Create a new Instance of a JWT from a part Array of an JWT
        /// </summary>
        /// <param name="parts">The parts as Array</param>
        public JwtParts(string[] parts) => _parts = parts;

        /// <summary>
        /// gets the Header of an JWT
        /// </summary>
        public string Header => _parts[(int)JwtPartsPointer.Header];
        /// <summary>
        /// gets the Payload of an JWT
        /// </summary>
        public string Payload => _parts[(int)JwtPartsPointer.Payload];

        /// <summary>
        /// gets the Signature of an JWT
        /// </summary>
        public string Signature => _parts[(int)JwtPartsPointer.Payload];

        /// <summary>
        /// gets the Parts of an JWT
        /// </summary>
        public string[] Parts => _parts.ToArray();

        /// <summary>
        /// Split a string representation of a JWT in to its parts
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
    }

    /// <summary>
    /// Helper Enum to get the right part from the array representation of JWT parts
    /// </summary>
    enum JwtPartsPointer
    {
        Header = 0,
        Payload = 1,
        Signature = 2
    }
}
