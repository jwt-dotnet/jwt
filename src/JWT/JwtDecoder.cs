using System;
using System.Collections.Generic;
using System.Text;
using JWT.Algorithms;

namespace JWT
{
    /// <summary>
    /// Decodes Jwt.
    /// </summary>
    public sealed class JwtDecoder : IJwtDecoder
    {
        private static readonly IAlgorithmFactory _defaultAlgorithmFactory = new HMACSHAAlgorithmFactory();

        private readonly IJsonSerializer _jsonSerializer;
        private readonly IJwtValidator _jwtValidator;
        private readonly IBase64UrlEncoder _urlEncoder;
        private readonly IAlgorithmFactory _algFactory;

        /// <summary>
        /// Creates an instance of <see cref="JwtDecoder" />.
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer.</param>
        /// <param name="jwtValidator">The Jwt Validator.</param>
        /// <param name="urlEncoder">The Base64 URL Encoder.</param>
        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator, IBase64UrlEncoder urlEncoder)
            : this(jsonSerializer, jwtValidator, urlEncoder, _defaultAlgorithmFactory)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtDecoder" />.
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer.</param>
        /// <param name="jwtValidator">The Jwt Validator.</param>
        /// <param name="urlEncoder">The Base64 URL Encoder.</param>
        /// <param name="algFactory">The Algorithm Factory.</param>
        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator, IBase64UrlEncoder urlEncoder, IAlgorithmFactory algFactory)
        {
            _jsonSerializer = jsonSerializer;
            _jwtValidator = jwtValidator;
            _urlEncoder = urlEncoder;
            _algFactory = algFactory;
        }

        /// <inheritdoc />
        public string Decode(string token) => Encoding.UTF8.GetString(_urlEncoder.Decode(new JwtParts(token).Payload));

        /// <inheritdoc />
        public string Decode(string token, string key, bool verify) => Decode(token, Encoding.UTF8.GetBytes(key), verify);

        /// <inheritdoc />
        public string Decode(string token, byte[] key, bool verify)
        {
            if (verify)
            {
                Validate(new JwtParts(token), key);
            }

            return Decode(token);
        }

        /// <inheritdoc />
        public IDictionary<string, object> DecodeToObject(string token) => DecodeToObject<Dictionary<string, object>>(token);

        /// <inheritdoc />
        public IDictionary<string, object> DecodeToObject(string token, string key, bool verify) => DecodeToObject(token, Encoding.UTF8.GetBytes(key), verify);

        /// <inheritdoc />
        public IDictionary<string, object> DecodeToObject(string token, byte[] key, bool verify) => DecodeToObject<Dictionary<string, object>>(token, key, verify);

        /// <inheritdoc />
        public T DecodeToObject<T>(string token) => _jsonSerializer.Deserialize<T>(Decode(token));

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, string key, bool verify) => DecodeToObject<T>(token, Encoding.UTF8.GetBytes(key), verify);

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, byte[] key, bool verify) => _jsonSerializer.Deserialize<T>(Decode(token, key, verify));

        /// <summary>
        /// Helper method that prepares data before calling <see cref="IJwtValidator.Validate" />.
        /// </summary>
        /// <param name="parts">The array representation of a JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        public void Validate(string[] parts, byte[] key) => Validate(new JwtParts(parts), key);

        /// <summary>
        /// Helper method that prepares data before calling <see cref="IJwtValidator.Validate" />.
        /// </summary>
        /// <param name="jwt">The JWT parts.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        public void Validate(JwtParts jwt, byte[] key)
        {
            var crypto = _urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var headerJson = Encoding.UTF8.GetString(_urlEncoder.Decode(jwt.Header));
            var headerData = _jsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);

            var payload = jwt.Payload;
            var payloadJson = Encoding.UTF8.GetString(_urlEncoder.Decode(payload));

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(jwt.Header, ".", payload));

            var algName = (string)headerData["alg"];
            var alg = _algFactory.Create(algName);

            var signatureData = alg.Sign(key, bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            _jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);
        }
    }
}