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
        public string Decode(string token, string key, bool verify)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <inheritdoc />
        public string Decode(string token, byte[] key, bool verify)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }

            var payload = parts[1];
            var payloadJson = Encoding.UTF8.GetString(_urlEncoder.Decode(payload));

            if (verify)
            {
                Validate(parts, key);
            }

            return payloadJson;
        }

        /// <inheritdoc />
        public IDictionary<string, object> DecodeToObject(string token, string key, bool verify)
        {
            return DecodeToObject(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <inheritdoc />
        public IDictionary<string, object> DecodeToObject(string token, byte[] key, bool verify)
        {
            var payloadJson = Decode(token, key, verify);
            return _jsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, string key, bool verify)
        {
            return DecodeToObject<T>(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, byte[] key, bool verify)
        {
            var payloadJson = Decode(token, key, verify);
            return _jsonSerializer.Deserialize<T>(payloadJson);
        }

        /// <summary>
        /// Helper method that prepares data before calling <see cref="IJwtValidator.Validate" />.
        /// </summary>
        /// <param name="parts">The JWT split into parts.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        public void Validate(string[] parts, byte[] key)
        {
            var crypto = _urlEncoder.Decode(parts[2]);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var header = parts[0];
            var headerJson = Encoding.UTF8.GetString(_urlEncoder.Decode(header));
            var headerData = _jsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);

            var payload = parts[1];
            var payloadJson = Encoding.UTF8.GetString(_urlEncoder.Decode(payload));

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));

            var algName = (string)headerData["alg"];
            var alg = _algFactory.Create(algName);

            var signatureData = alg.Sign(key, bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            _jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);
        }
    }
}