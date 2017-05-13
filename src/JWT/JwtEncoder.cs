using System.Collections.Generic;
using System.Text;

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
        /// Creates an instance of <see cref="JwtEncoder" />.
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer.</param>
        /// <param name="algorithm">The Jwt Algorithm.</param>
        /// <param name="urlEncoder">The Base64 URL Encoder.</param>
        public JwtEncoder(IJwtAlgorithm algorithm, IJsonSerializer jsonSerializer, IBase64UrlEncoder urlEncoder)
        {
            _algorithm = algorithm;
            _jsonSerializer = jsonSerializer;
            _urlEncoder = urlEncoder;
        }

        /// <inheritdoc />
        public string Encode(object payload, string key)
        {
            return Encode(null, payload, Encoding.UTF8.GetBytes(key));
        }

        /// <inheritdoc />
        public string Encode(object payload, byte[] key)
        {
            return Encode(null, payload, key);
        }

        /// <inheritdoc />
        public string Encode(IDictionary<string, object> extraHeaders, object payload, string key)
        {
            return Encode(extraHeaders, payload, Encoding.UTF8.GetBytes(key));
        }

        /// <inheritdoc />
        public string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key)
        {
            var segments = new List<string>(3);

            var header = extraHeaders != null ? new Dictionary<string, object>(extraHeaders) : new Dictionary<string, object>();
            header.Add("typ", "JWT");
            header.Add("alg", _algorithm.Name);

            var headerBytes = Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(header));
            var payloadBytes = Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(payload));

            segments.Add(_urlEncoder.Encode(headerBytes));
            segments.Add(_urlEncoder.Encode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());
            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            var signature = _algorithm.Sign(key, bytesToSign);
            segments.Add(_urlEncoder.Encode(signature));

            return string.Join(".", segments.ToArray());
        }
    }
}
