using System;
using System.Collections.Generic;

using static JWT.Internal.EncodingHelper;

namespace JWT
{
    /// <summary>
    /// Extension methods for <seealso cref="IJwtDecoder" />
    ///</summary>
    public static class JwtDecoderExtensions
    {
        #region DecodeHeader

        public static IDictionary<string, string> DecodeHeaderToObject(this IJwtDecoder decoder, string token) =>
            decoder.DecodeHeaderToObject<Dictionary<string, string>>(token);

        #endregion

        #region Decode

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public static string Decode(this IJwtDecoder decoder, string token, string key, bool verify) =>
            decoder.Decode(token, GetBytes(key), verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The key which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public static string Decode(this IJwtDecoder decoder, string token, string[] keys, bool verify) =>
            decoder.Decode(token, GetBytes(keys), verify);

        #endregion

        #region DecodeToObject

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <returns>An object representing the payload</returns>
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token) =>
            decoder.DecodeToObject<Dictionary<string, object>>(token);

        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, string key, bool verify) =>
            decoder.DecodeToObject(token, GetBytes(key), verify);

        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, string[] keys, bool verify) =>
            decoder.DecodeToObject(token, GetBytes(keys), verify);

        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, byte[] key, bool verify) =>
            decoder.DecodeToObject<Dictionary<string, object>>(token, key, verify);

        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, byte[][] keys, bool verify) =>
            decoder.DecodeToObject<Dictionary<string, object>>(token, keys, verify);

        #endregion

        #region DecodeToObject<T>

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, string key, bool verify) =>
            decoder.DecodeToObject<T>(token, GetBytes(key), verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, string[] keys, bool verify) =>
            decoder.DecodeToObject<T>(token, GetBytes(keys), verify);

        #endregion
    }
}