using System;
using JWT.Internal;

#if NET8_0_OR_GREATER
using System.Buffers.Text;
#endif

#if NET35
using static JWT.Compatibility.String;
#else
using static System.String;
#endif

namespace JWT
{
    /// <summary>
    /// base64 encoding/decoding implementation according to the JWT spec
    /// </summary>
    public sealed class JwtBase64UrlEncoder : IBase64UrlEncoder
    {
        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public string Encode(byte[] input)
        {
            if (input is null)
                throw new ArgumentNullException(nameof(input));
            if (input.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(input));

#if NET8_0_OR_GREATER
            return Base64Url.EncodeToString(input);
#else
            var output = Convert.ToBase64String(input);
            output = output.FirstSegment('='); // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
#endif
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="FormatException" />
        public byte[] Decode(string input)
        {
            if (IsNullOrWhiteSpace(input))
                throw new ArgumentException(nameof(input));

#if NET8_0_OR_GREATER
            // Base64Url skips whitespace, which is not valid in base64url-encoded JWT segments
            if (input.AsSpan().IndexOfAny(" \t\r\n") >= 0)
                throw new FormatException("Illegal base64url string.");

            return Base64Url.DecodeFromChars(input);
#else
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
                    throw new FormatException("Illegal base64url string.");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
#endif
        }
    }
}
