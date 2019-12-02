using System;
using System.Collections.Generic;
using System.Linq;
using JWT.Algorithms;

using static JWT.Internal.EncodingHelper;

namespace JWT
{
    /// <summary>
    /// Decodes JWT.
    /// </summary>
    public sealed class JwtDecoder : IJwtDecoder
    {
        private readonly IJsonSerializer _jsonSerializer;
        private readonly IJwtValidator _jwtValidator;
        private readonly IBase64UrlEncoder _urlEncoder;
        private readonly IAlgorithmFactory _algFactory;

        /// <summary>
        /// Creates an instance of <see cref="JwtDecoder" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="jwtValidator">The Jwt validator</param>
        /// <param name="urlEncoder">The Base64 URL Encoder</param>
        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator, IBase64UrlEncoder urlEncoder)
            : this(jsonSerializer, jwtValidator, urlEncoder, new HMACSHAAlgorithmFactory())
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtDecoder" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="jwtValidator">The Jwt validator</param>
        /// <param name="urlEncoder">The Base64 URL Encoder</param>
        /// <param name="algFactory">The Algorithm Factory</param>
        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator, IBase64UrlEncoder urlEncoder, IAlgorithmFactory algFactory)
        {
            _jsonSerializer = jsonSerializer;
            _jwtValidator = jwtValidator;
            _urlEncoder = urlEncoder;
            _algFactory = algFactory;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public string Decode(JwtParts jwt)
        {
            var decoded = _urlEncoder.Decode(jwt.Payload);
            return GetString(decoded);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public string Decode(string token)
        {
            var payload = new JwtParts(token).Payload;
            var decoded = _urlEncoder.Decode(payload);
            return GetString(decoded);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public string Decode(string token, string key, bool verify) =>
            Decode(token, GetBytes(key), verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public string Decode(string token, string[] keys, bool verify) =>
            Decode(token, GetBytes(keys), verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public string Decode(string token, byte[] key, bool verify)
        {
            if (String.IsNullOrWhiteSpace(token))
                throw new ArgumentException(nameof(token));
            if (key is null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(key));

            if (verify)
            {
                Validate(new JwtParts(token), key);
            }

            return Decode(token);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public string Decode(string token, byte[][] keys, bool verify)
        {
            if (String.IsNullOrWhiteSpace(token))
                throw new ArgumentException(nameof(token));
            if (keys is null)
                throw new ArgumentNullException(nameof(keys));
            if (keys.Length == 0 || !AllKeysHaveValues(keys))
                throw new ArgumentOutOfRangeException(nameof(keys));

            var jwt = new JwtParts(token);

            if (verify)
            {
                Validate(jwt, keys);
            }

            return Decode(jwt);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public IDictionary<string, object> DecodeToObject(string token) =>
            DecodeToObject<Dictionary<string, object>>(token);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public IDictionary<string, object> DecodeToObject(string token, string key, bool verify) =>
            DecodeToObject(token, GetBytes(key), verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public IDictionary<string, object> DecodeToObject(string token, string[] keys, bool verify) =>
            DecodeToObject(token, GetBytes(keys), verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public IDictionary<string, object> DecodeToObject(string token, byte[] key, bool verify) =>
            DecodeToObject<Dictionary<string, object>>(token, key, verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public IDictionary<string, object> DecodeToObject(string token, byte[][] keys, bool verify) =>
            DecodeToObject<Dictionary<string, object>>(token, keys, verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public T DecodeToObject<T>(string token)
        {
            var payload = Decode(token);
            return _jsonSerializer.Deserialize<T>(payload);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public T DecodeToObject<T>(string token, string key, bool verify) =>
            DecodeToObject<T>(token, GetBytes(key), verify);

        public T DecodeToObject<T>(string token, string[] keys, bool verify) =>
            DecodeToObject<T>(token, GetBytes(keys), verify);

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public T DecodeToObject<T>(string token, byte[] key, bool verify)
        {
            var payload = Decode(token, key, verify);
            return _jsonSerializer.Deserialize<T>(payload);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public T DecodeToObject<T>(string token, byte[][] keys, bool verify)
        {
            var payload = Decode(token, keys, verify);
            return _jsonSerializer.Deserialize<T>(payload);
        }

        /// <summary>
        /// Prepares data before calling <see cref="IJwtValidator.Validate" />
        /// </summary>
        /// <param name="parts">The array representation of a JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public void Validate(string[] parts, params byte[] key) =>
            Validate(new JwtParts(parts), key);

        /// <summary>
        /// Prepares data before calling <see cref="IJwtValidator.Validate" />
        /// </summary>
        /// <param name="jwt">The JWT parts</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public void Validate(JwtParts jwt, params byte[][] keys)
        {
            if (jwt is null)
                throw new ArgumentNullException(nameof(jwt));
            if (keys is null)
                throw new ArgumentNullException(nameof(keys));
            if (keys.Length == 0 || !AllKeysHaveValues(keys))
                throw new ArgumentOutOfRangeException(nameof(keys));

            var crypto = _urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var headerJson = GetString(_urlEncoder.Decode(jwt.Header));
            var headerData = _jsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);

            var payload = jwt.Payload;
            var payloadJson = GetString(_urlEncoder.Decode(payload));

            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", payload));

            var algName = (string)headerData["alg"];
            var alg = _algFactory.Create(algName);

            var decodedSignatures = keys.Select(key => alg.Sign(key, bytesToSign))
                                        .Select(sd => Convert.ToBase64String(sd))
                                        .ToArray();

            _jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignatures);
        }

        private static bool AllKeysHaveValues(IEnumerable<byte[]> keys) =>
            keys.All(key => key.Any());
    }
}