using System;

namespace JWT
{
    /// <summary>
    /// Base64 encoding/decoding implementation according to the JWT spec
    /// </summary>
    public sealed class JwtBase64UrlEncoder : IBase64UrlEncoder
    {
        /// <summary>
        /// Encode the byte array to a Base64 string.
        /// </summary>
        /// <param name="input"></param>
        public string Encode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        /// <summary>
        /// Decode the Base64 string to a byte array.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] Decode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    output += "==";
                    break; // Two pad chars
                case 3:
                    output += "=";
                    break; // One pad char
                default:
                    throw new FormatException("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}
