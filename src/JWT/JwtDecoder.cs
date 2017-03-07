using System;
using System.Collections.Generic;
using System.Text;

namespace JWT
{
    public sealed class JwtDecoder : IJwtDecoder
    {
        private static readonly AlgorithmFactory _algFactory = new AlgorithmFactory();

        private readonly IJsonSerializer _jsonSerializer;
        private readonly IJwtValidator _jwtValidator;

        public JwtDecoder(IJsonSerializer jsonSerializer, IJwtValidator jwtValidator)
        {
            _jsonSerializer = jsonSerializer;
            _jwtValidator = jwtValidator;
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
            var payloadJson = Encoding.UTF8.GetString(JsonWebToken.Base64UrlDecode(payload));

            if (verify)
            {
                Validate(payload, payloadJson, parts, key);
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

        private void Validate(string payload, string payloadJson, string[] parts, byte[] key)
        {
            var crypto = JsonWebToken.Base64UrlDecode(parts[2]);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var header = parts[0];
            var headerJson = Encoding.UTF8.GetString(JsonWebToken.Base64UrlDecode(header));
            var headerData = _jsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));

            var algName = (string)headerData["alg"];
            var alg = _algFactory.Create(algName);

            var signatureData = alg.Sign(key, bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            _jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);
        }
    }
}