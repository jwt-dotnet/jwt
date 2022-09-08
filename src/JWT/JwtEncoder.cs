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
        private readonly IAlgorithmFactory _algFactory;
        private readonly IJsonSerializer _jsonSerializer;
        private readonly IBase64UrlEncoder _urlEncoder;

        /// <summary>
        /// Creates an instance of <see cref="JwtEncoder" />
        /// </summary>
        /// <param name="algFactory">The JWT algorithm factory</param>
        /// <param name="jsonSerializer">The JSON serializer</param>
        /// <param name="urlEncoder">The base64 URL encoder</param>
        public JwtEncoder(IAlgorithmFactory algFactory, IJsonSerializer jsonSerializer, IBase64UrlEncoder urlEncoder)
        {
            _algFactory = algFactory;
            _jsonSerializer = jsonSerializer;
            _urlEncoder = urlEncoder;
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtEncoder" />
        /// </summary>
        /// <param name="algorithm">The JWT algorithm</param>
        /// <param name="jsonSerializer">The JSON serializer</param>
        /// <param name="urlEncoder">The base64 URL encoder</param>
        public JwtEncoder(IJwtAlgorithm algorithm, IJsonSerializer jsonSerializer, IBase64UrlEncoder urlEncoder)
            : this(new DelegateAlgorithmFactory(algorithm), jsonSerializer, urlEncoder)
        {
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key)
        {
            if (payload is null)
                throw new ArgumentNullException(nameof(payload));

            var algorithm = _algFactory.Create(null);
            if (algorithm is null)
                throw new ArgumentNullException(nameof(algorithm));
            if (!algorithm.IsAsymmetric() && key is null && algorithm is not NoneAlgorithm)
                throw new ArgumentNullException(nameof(key));

            var header = extraHeaders is null ?
                new Dictionary<string, object>(2, StringComparer.OrdinalIgnoreCase) :
                new Dictionary<string, object>(extraHeaders, StringComparer.OrdinalIgnoreCase);

            if (!header.ContainsKey("typ"))
            {
                header.Add("typ", "JWT");
            }
            header.Add("alg", algorithm.Name);

            var headerBytes = GetBytes(_jsonSerializer.Serialize(header));
            var payloadBytes = GetBytes(_jsonSerializer.Serialize(payload));

            var headerSegment = _urlEncoder.Encode(headerBytes);
            var payloadSegment = _urlEncoder.Encode(payloadBytes);

            var stringToSign = headerSegment + "." + payloadSegment;
            var bytesToSign = GetBytes(stringToSign);

            var signatureSegment = GetSignatureSegment(algorithm, key, bytesToSign);
            return stringToSign + "." + signatureSegment;
        }

        private string GetSignatureSegment(IJwtAlgorithm algorithm, byte[] key, byte[] bytesToSign)
        {
            switch (algorithm)
            {
                case NoneAlgorithm _:
                {
                    return null;
                }
                default:
                {
                    var signature = algorithm.Sign(key, bytesToSign);
                    return _urlEncoder.Encode(signature);
                }
            }
        }
    }
}