using System;
using System.Collections.Generic;
using JWT.Algorithms;

using static JWT.Internal.EncodingHelper;

namespace JWT
{
    /// <summary>
    /// Encodes Jwt.
    /// </summary>
    public sealed class JwtEncoder : IJwtEncoder
    {
        private readonly IJwtAlgorithm _algorithm;
        private readonly IJsonSerializer _jsonSerializer;
        private readonly IBase64UrlEncoder _urlEncoder;

        /// <summary>
        /// Creates an instance of <see cref="JwtEncoder" />
        /// </summary>
        /// <param name="algorithm">The Jwt Algorithm</param>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="urlEncoder">The Base64 URL Encoder</param>
        public JwtEncoder(IJwtAlgorithm algorithm, IJsonSerializer jsonSerializer, IBase64UrlEncoder urlEncoder)
        {
            _algorithm = algorithm;
            _jsonSerializer = jsonSerializer;
            _urlEncoder = urlEncoder;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key)
        {
            if (payload is null)
                throw new ArgumentNullException(nameof(payload));
            if (!_algorithm.IsAsymmetric() && key is null)
                throw new ArgumentNullException(nameof(key));

            var header = extraHeaders is null ?
                new Dictionary<string, object>(2, StringComparer.OrdinalIgnoreCase) :
                new Dictionary<string, object>(extraHeaders, StringComparer.OrdinalIgnoreCase);

            if (!header.ContainsKey("typ"))
                header.Add("typ", "JWT");
            header.Add("alg", _algorithm.Name);

            var headerBytes = GetBytes(_jsonSerializer.Serialize(header));
            var payloadBytes = GetBytes(_jsonSerializer.Serialize(payload));

            var headerSegment = _urlEncoder.Encode(headerBytes);
            var payloadSegment = _urlEncoder.Encode(payloadBytes);

            var stringToSign = headerSegment + "." + payloadSegment;
            var bytesToSign = GetBytes(stringToSign);

            var signature = _algorithm.Sign(key, bytesToSign);
            var signatureSegment = _urlEncoder.Encode(signature);

            return stringToSign + "." + signatureSegment;
        }
    }
}