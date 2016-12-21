using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JWT
{
    /// <summary>
    /// Provides methods for encoding and decoding JSON Web Tokens.
    /// </summary>
    public static class JsonWebToken
    {
        private static readonly IDictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> HashAlgorithms;

        /// <summary>
        /// Pluggable JSON Serializer
        /// </summary>
        public static IJsonSerializer JsonSerializer = new DefaultJsonSerializer();

        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        static JsonWebToken()
        {
            HashAlgorithms = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } }
            };
        }

        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(object payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(new Dictionary<string, object>(), payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            return Encode(new Dictionary<string, object>(), payload, key, algorithm);
        }

        /// <summary>
        /// Creates a JWT given a set of arbitrary extra headers, a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="extraHeaders">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers.</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="key">The key bytes used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(IDictionary<string, object> extraHeaders, object payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(extraHeaders, payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        /// <summary>
        /// Creates a JWT given a header, a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="extraHeaders">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers.</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON via <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).</param>
        /// <param name="key">The key bytes used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            var segments = new List<string>();
            var header = new Dictionary<string, object>(extraHeaders)
            {
                { "typ", "JWT" },
                { "alg", algorithm.ToString() }
            };

            var headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
            var payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());
            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            var signature = HashAlgorithms[algorithm](key, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        /// <summary>
        /// Given a JWT, decode it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim.</exception>
        public static string Decode(string token, string key, bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Given a JWT, decode it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key bytes that were used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim.</exception>
        public static string Decode(string token, byte[] key, bool verify = true)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }

            var payload = parts[1];
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));

            if (verify)
            {
                Verify(payload, payloadJson, parts, key);
            }

            return payloadJson;
        }

        /// <summary>
        /// Given a JWT, decode it and return the payload as an object (by deserializing it with <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim.</exception>
        public static object DecodeToObject(string token, string key, bool verify = true)
        {
            return DecodeToObject(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Given a JWT, decode it and return the payload as an object (by deserializing it with <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim.</exception>
        public static object DecodeToObject(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            return JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
        }

        /// <summary>
        /// Given a JWT, decode it and return the payload as an object (by deserializing it with <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).
        /// </summary>
        /// <typeparam name="T">The <see cref="Type"/> to return</typeparam>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim.</exception>
        public static T DecodeToObject<T>(string token, string key, bool verify = true)
        {
            return DecodeToObject<T>(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Given a JWT, decode it and return the payload as an object (by deserializing it with <see cref="System.Web.Script.Serialization.JavaScriptSerializer"/>).
        /// </summary>
        /// <typeparam name="T">The <see cref="Type"/> to return</typeparam>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim.</exception>
        public static T DecodeToObject<T>(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            return JsonSerializer.Deserialize<T>(payloadJson);
        }

        /// <remarks>From JWT spec</remarks>
        public static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        /// <remarks>From JWT spec</remarks>
        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break;  // One pad char
                default: throw new FormatException("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

        /// <summary>
        /// Given the JWT, verifies it.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON).</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signature</param>
        /// <exception cref="SignatureVerificationException">The signature is invalid.</exception>
        /// <exception cref="TokenExpiredException">The token has expired.</exception>
        public static void Verify(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            if (decodedCrypto != decodedSignature)
            {
                throw new SignatureVerificationException("Invalid signature")
                {
                    Expected = decodedCrypto,
                    Received = decodedSignature
                };
            }

            // verify exp claim https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            object expObj;
            if (!payloadData.TryGetValue("exp", out expObj) || expObj == null)
            {
                return;
            }
            int expInt;
            try
            {
                expInt = Convert.ToInt32(expObj);
            }
            catch (FormatException)
            {
                throw new SignatureVerificationException("Claim 'exp' must be an integer.");
            }
            var secondsSinceEpoch = Math.Round((DateTime.UtcNow - UnixEpoch).TotalSeconds);
            if (secondsSinceEpoch >= expInt)
            {
                throw new TokenExpiredException("Token has expired.")
                {
                    Expiration = UnixEpoch.AddSeconds(expInt),
                    PayloadData = payloadData
                };
            }
        }

        private static void Verify(string payload, string payloadJson, string[] parts, byte[] key)
        {
            var crypto = Base64UrlDecode(parts[2]);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var header = parts[0];
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            var headerData = JsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);
            var algorithm = (string)headerData["alg"];

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
            var signatureData = HashAlgorithms[GetHashAlgorithm(algorithm)](key, bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            Verify(payloadJson, decodedCrypto, decodedSignature);
        }

        private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "HS256": return JwtHashAlgorithm.HS256;
                case "HS384": return JwtHashAlgorithm.HS384;
                case "HS512": return JwtHashAlgorithm.HS512;
                default: throw new SignatureVerificationException("Algorithm not supported.");
            }
        }
    }
}