using System;
using System.Collections.Generic;
using JWT.Exceptions;

using static JWT.Internal.EncodingHelper;

namespace JWT
{
    /// <summary>
    /// Represents a JWT decoder.
    /// </summary>
    public interface IJwtDecoder
    {
        #region DecodeHeader

        /// <summary>
        /// Given a JWT, decodes it and return the header.
        /// </summary>
        /// <param name="token">The JWT</param>
        string DecodeHeader(string token);

        /// <summary>
        /// Given a JWT, decodes it and return the header as an object.
        /// </summary>
        /// <param name="jwt">The JWT</param>
        T DecodeHeader<T>(JwtParts jwt);

        #endregion

        #region Decode
        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="jwt">The JWT</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(JwtParts jwt);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="jwt">The JWT</param>
        /// <param name="key">The key that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(JwtParts jwt, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="jwt">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(JwtParts jwt, byte[][] keys, bool verify);

        #endregion

        #region T DecodeToObject<T>

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="jwt">The JWT</param>
        /// <returns>An object representing the payload</returns>
        T DecodeToObject<T>(JwtParts jwt);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="jwt">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        T DecodeToObject<T>(JwtParts jwt, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="jwt">The JWT</param>
        /// <param name="keys">The keys which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        T DecodeToObject<T>(JwtParts jwt, byte[][] keys, bool verify);

        #endregion
    }

    /// <summary>
    /// Extension methods for <seealso cref="IJwtDecoder" />
    ///</summary>
    public static class JwtDecoderExtensions
    {
        #region DecodeHeader

        public static T DecodeHeader<T>(this IJwtDecoder decoder, string token) =>
            decoder.DecodeHeader<T>(new JwtParts(token));

        public static IDictionary<string, string> DecodeHeaderToDictionary(this IJwtDecoder decoder, string token) =>
            decoder.DecodeHeader<Dictionary<string, string>>(token);

        #endregion

        #region Decode

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static string Decode(this IJwtDecoder decoder, string token) =>
            decoder.Decode(new JwtParts(token));

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="jwt">The JWT</param>
        /// <returns>A string containing the JSON payload</returns>
        public static string Decode(this IJwtDecoder decoder, JwtParts jwt) =>
            decoder.Decode(jwt, (byte[])null, verify: false);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static string Decode(this IJwtDecoder decoder, string token, byte[] key, bool verify) =>
            decoder.Decode(new JwtParts(token), key, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static string Decode(this IJwtDecoder decoder, string token, byte[][] keys, bool verify) =>
            decoder.Decode(new JwtParts(token), keys, verify);

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
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token) =>
            decoder.DecodeToObject<T>(new JwtParts(token));

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

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref = "ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, byte[] key, bool verify) =>
            decoder.DecodeToObject<Dictionary<string, object>>(new JwtParts(token), key, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, byte[][] keys, bool verify) =>
            decoder.DecodeToObject<Dictionary<string, object>>(new JwtParts(token), keys, verify);

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
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, byte[] key, bool verify) =>
            decoder.DecodeToObject<T>(new JwtParts(token), key, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, byte[][] keys, bool verify) =>
            decoder.DecodeToObject<T>(new JwtParts(token), keys, verify);

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