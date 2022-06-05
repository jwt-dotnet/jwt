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
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(JwtParts jwt, bool verify);

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

        #region DecodeToObject

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="jwt">The JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        object DecodeToObject(Type type, JwtParts jwt, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="jwt">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        object DecodeToObject(Type type, JwtParts jwt, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="jwt">The JWT</param>
        /// <param name="keys">The keys which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        object DecodeToObject(Type type, JwtParts jwt, byte[][] keys, bool verify);

        #endregion
    }

    /// <summary>
    /// Extension methods for <seealso cref="IJwtDecoder" />>
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
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static string Decode(this IJwtDecoder decoder, string token, bool verify = true) =>
            decoder.Decode(new JwtParts(token), (byte[])null, verify);

        /// <summary>
        /// Given a JWT, decodes it, and return the payload.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static string Decode(this IJwtDecoder decoder, string token, byte[] key, bool verify = true) =>
            decoder.Decode(new JwtParts(token), new[] { key }, verify);

        /// <summary>
        /// Given a JWT, decodes it, and return the payload.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static string Decode(this IJwtDecoder decoder, string token, byte[][] keys, bool verify = true) =>
            decoder.Decode(new JwtParts(token), keys, verify);

        /// <summary>
        /// Given a JWT, decodes it, and return the payload as an dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public static string Decode(this IJwtDecoder decoder, string token, string key, bool verify = true) =>
            decoder.Decode(token, new[] { key }, verify);

        /// <summary>
        /// Given a JWT, decodes it, and return the payload as an dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The key which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public static string Decode(this IJwtDecoder decoder, string token, string[] keys, bool verify = true) =>
            decoder.Decode(token, GetBytes(keys), verify);

        #endregion

        #region DecodeToObject

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, bool verify = true) =>
            decoder.DecodeToObject<Dictionary<string, object>>(token, (byte[])null, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, string key, bool verify = true) =>
            decoder.DecodeToObject(token, new[] { key }, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, string[] keys, bool verify = true) =>
            decoder.DecodeToObject(token, GetBytes(keys), verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref = "ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, byte[] key, bool verify = true) =>
            decoder.DecodeToObject<Dictionary<string, object>>(new JwtParts(token), new[] { key }, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static IDictionary<string, object> DecodeToObject(this IJwtDecoder decoder, string token, byte[][] keys, bool verify = true) =>
            decoder.DecodeToObject<Dictionary<string, object>>(new JwtParts(token), keys, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref = "ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static object DecodeToObject(this IJwtDecoder decoder, Type type, string token, byte[] key, bool verify = true) =>
            decoder.DecodeToObject(type, new JwtParts(token), new[] { key }, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as a dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>A string containing the JSON payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="InvalidTokenPartsException" />
        public static object DecodeToObject(this IJwtDecoder decoder, Type type, string token, byte[][] keys, bool verify = true) =>
            decoder.DecodeToObject(type, new JwtParts(token), keys, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public static object DecodeToObject(this IJwtDecoder decoder, Type type, string token, string key, bool verify = true) =>
            decoder.DecodeToObject(type, token, new[] { key }, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an dictionary.
        /// </summary>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="type">The type to deserialize to.</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The key which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public static object DecodeToObject(this IJwtDecoder decoder, Type type, string token, string[] keys, bool verify = true) =>
            decoder.DecodeToObject(type, token, GetBytes(keys), verify);

        #endregion

        #region DecodeToObject<T>

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to deserialize to.</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="jwt">The JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, JwtParts jwt, bool verify = true) =>
            (T)decoder.DecodeToObject(typeof(T), jwt, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to deserialize to.</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="jwt">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, JwtParts jwt, byte[] key, bool verify = true) =>
            (T)decoder.DecodeToObject(typeof(T), jwt, key, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to deserialize to.</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="jwt">The JWT</param>
        /// <param name="keys">The keys which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, JwtParts jwt, byte[][] keys, bool verify = true) =>
            (T)decoder.DecodeToObject(typeof(T), jwt, keys, verify);

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
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, string key, bool verify = true) =>
            decoder.DecodeToObject<T>(token, GetBytes(key), verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, byte[] key, bool verify = true) =>
            decoder.DecodeToObject<T>(new JwtParts(token), key, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, byte[][] keys, bool verify = true) =>
            decoder.DecodeToObject<T>(new JwtParts(token), keys, verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="decoder">The decoder instance</param>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is <c>true</c>)</param>
        /// <returns>An object representing the payload</returns>
        public static T DecodeToObject<T>(this IJwtDecoder decoder, string token, string[] keys, bool verify = true) =>
            decoder.DecodeToObject<T>(token, GetBytes(keys), verify);

        #endregion
    }
}
