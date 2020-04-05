using System;
using System.Collections.Generic;
using System.Linq;
using JWT.Algorithms;
using JWT.Builder;

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
        /// <remarks>
        /// This overload supplies no <see cref="IJwtValidator" /> and no <see cref="IAlgorithmFactory" /> so the resulting decoder cannot be used for signature validation.
        /// </remarks>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="urlEncoder">The Base64 URL Encoder</param>
        /// <exception cref="ArgumentNullException" />
        public JwtDecoder(IJsonSerializer jsonSerializer, IBase64UrlEncoder urlEncoder)
        {
            _jsonSerializer = jsonSerializer ?? throw new ArgumentNullException(nameof(jsonSerializer));
            _urlEncoder = urlEncoder ?? throw new ArgumentNullException(nameof(urlEncoder));
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtDecoder" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="jwtValidator">The Jwt validator</param>
        /// <param name="urlEncoder">The Base64 URL Encoder</param>
        /// <param name="algFactory">The Algorithm Factory</param>
        /// <exception cref="ArgumentNullException" />
        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator, IBase64UrlEncoder urlEncoder, IAlgorithmFactory algFactory)
            : this(jsonSerializer, urlEncoder)
        {
            _jwtValidator = jwtValidator ?? throw new ArgumentNullException(nameof(jwtValidator));
            _algFactory = algFactory ?? throw new ArgumentNullException(nameof(algFactory));
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtDecoder" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="jwtValidator">The Jwt validator</param>
        /// <param name="urlEncoder">The Base64 URL Encoder</param>
        /// <param name="algorithm">The Algorithm</param>
        /// <exception cref="ArgumentNullException" />
        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator, IBase64UrlEncoder urlEncoder, IJwtAlgorithm algorithm)
            : this(jsonSerializer, jwtValidator, urlEncoder, new DelegateAlgorithmFactory(algorithm))
        {
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        public string DecodeHeader(string token)
        {
            if (String.IsNullOrEmpty(token))
                throw new ArgumentException(nameof(token));

            var header = new JwtParts(token).Header;
            var decoded = _urlEncoder.Decode(header);
            return GetString(decoded);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public T DecodeHeader<T>(JwtParts jwt)
        {
            if (jwt is null)
                throw new ArgumentNullException(nameof(jwt));

            var decodedHeader = _urlEncoder.Decode(jwt.Header);
            var stringHeader = GetString(decodedHeader);
            return _jsonSerializer.Deserialize<T>(stringHeader);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public string Decode(JwtParts jwt)
        {
            if (jwt is null)
                throw new ArgumentNullException(nameof(jwt));

            var decoded = _urlEncoder.Decode(jwt.Payload);
            return GetString(decoded);
        }

        /// <inheritdoc />
        public string Decode(string token)
        {
            var payload = new JwtParts(token).Payload;
            var decoded = _urlEncoder.Decode(payload);
            return GetString(decoded);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public string Decode(string token, byte[] key, bool verify)
        {
            if (String.IsNullOrWhiteSpace(token))
                throw new ArgumentException(nameof(token));
            if (key is object && key.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(key));

            var jwt = new JwtParts(token);

            if (verify)
            {
                if (_jwtValidator is null || _algFactory is null)
                    throw new InvalidOperationException("This instance was constructed without validator and algorithm so cannot be used for signature validation");

                Validate(jwt, key);
            }

            return Decode(jwt);
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        public string Decode(string token, byte[][] keys, bool verify)
        {
            if (String.IsNullOrWhiteSpace(token))
                throw new ArgumentException(nameof(token));
            if (!AllKeysHaveValues(keys))
                throw new ArgumentOutOfRangeException(nameof(keys));

            var jwt = new JwtParts(token);

            if (verify)
            {
                if (_jwtValidator is null || _algFactory is null)
                    throw new InvalidOperationException("This instance was constructed without validator and algorithm so cannot be used for signature validation");

                Validate(jwt, keys);
            }

            return Decode(jwt);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token)
        {
            var payload = Decode(token);
            return _jsonSerializer.Deserialize<T>(payload);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, byte[] key, bool verify)
        {
            var payload = Decode(token, key, verify);
            return _jsonSerializer.Deserialize<T>(payload);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, byte[][] keys, bool verify)
        {
            var payload = Decode(token, keys, verify);
            return _jsonSerializer.Deserialize<T>(payload);
        }

        /// <summary>
        /// Prepares data before calling <see cref="IJwtValidator" />
        /// </summary>
        /// <param name="parts">The array representation of a JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public void Validate(string[] parts, byte[] key) =>
            Validate(new JwtParts(parts), key);

        /// <summary>
        /// Prepares data before calling <see cref="IJwtValidator" />
        /// </summary>
        /// <param name="parts">The array representation of a JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentOutOfRangeException" />
        /// <exception cref="FormatException" />
        public void Validate(string[] parts, params byte[][] keys) =>
            Validate(new JwtParts(parts), keys);

        /// <summary>
        /// Prepares data before calling <see cref="IJwtValidator" />
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
            if (!AllKeysHaveValues(keys))
                throw new ArgumentOutOfRangeException(nameof(keys));

            var decodedPayload = GetString(_urlEncoder.Decode(jwt.Payload));
            var decodedSignature = _urlEncoder.Decode(jwt.Signature);

            var header = DecodeHeader<JwtHeader>(jwt);
            var alg = _algFactory.Create(header.Algorithm);

            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));

            if (alg is IAsymmetricAlgorithm asymmAlg)
            {
                _jwtValidator.Validate(decodedPayload, asymmAlg, bytesToSign, decodedSignature);
            }
            else
            {
                // the signature on the token, with the leading =
                var rawSignature = Convert.ToBase64String(decodedSignature);

                // the signatures re-created by the algorithm, with the leading =
                var recreatedSignatures = keys.Select(key => alg.Sign(key, bytesToSign))
                                              .Select(sd => Convert.ToBase64String(sd))
                                              .ToArray();

                _jwtValidator.Validate(decodedPayload, rawSignature, recreatedSignatures);
            }
        }

        private static bool AllKeysHaveValues(IReadOnlyCollection<byte[]> keys)
        {
            if (keys is null)
                return true;

            if (keys.Count == 0)
                return false;

            return keys.All(key => key.Any());
        }
    }
}