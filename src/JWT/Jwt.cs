using System;
using System.Linq;

namespace JWT
{
    /// <summary>
    /// A class that represent a JWT
    /// </summary>
    internal class Jwt
    {
        /// <summary>
        /// A array that have length of 3, because the JWT have 3 Parts
        /// </summary>
        private readonly string[] _parts;

        /// <summary>
        /// Creates a new Instance of JWT from a JWT-String
        /// </summary>
        /// <param name="token">The JWT as string</param>
        public Jwt(string token): this(SplitToken(token)) { }

        /// <summary>
        /// Create a new Instance of a JWT from a part Array of an JWT
        /// </summary>
        /// <param name="parts">The parts as Array</param>
        public Jwt(string[] parts) => _parts = parts;

        /// <summary>
        /// gets the Header of an JWT
        /// </summary>
        public string Header => _parts[(int)JwtParts.Header];
        /// <summary>
        /// gets the Payload of an JWT
        /// </summary>
        public string Payload => _parts[(int)JwtParts.Payload];

        /// <summary>
        /// gets the Signature of an JWT
        /// </summary>
        public string Signature => _parts[(int)JwtParts.Payload];

        /// <summary>
        /// gets the Parts of an JWT
        /// </summary>
        public string[] Parts => _parts.ToArray();

        /// <summary>
        /// Split a JWT-String in to its parts
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
    /// Helper Enum to get the right part from a JWT-Parts-Array
    /// </summary>
    enum JwtParts
    {
        Header = 0,
        Payload = 1,
        Signature = 2
    }
}
