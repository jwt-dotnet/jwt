using System;
using System.Collections.Generic;
using JWT.Algorithms;

using static JWT.Internal.EncodingHelper;

#if NET8_0_OR_GREATER
using System.Buffers;
#endif

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

            var headerJson = _jsonSerializer.Serialize(header);
#if NET8_0_OR_GREATER
            if (_urlEncoder is JwtBase64UrlEncoder && !String.IsNullOrEmpty(headerJson) &&
                (algorithm is NoneAlgorithm || algorithm.AsSpanAlgorithm() is not null))
            {
                var payloadJson = _jsonSerializer.Serialize(payload);
                if (!String.IsNullOrEmpty(payloadJson))
                    return EncodeWithSpans(algorithm, key, headerJson, payloadJson);

                return Encode(algorithm, key, GetBytes(headerJson), GetBytes(payloadJson));
            }
#endif
            var headerBytes = GetBytes(headerJson);
            var payloadBytes = GetBytes(_jsonSerializer.Serialize(payload));
            return Encode(algorithm, key, headerBytes, payloadBytes);
        }

        private string Encode(IJwtAlgorithm algorithm, byte[] key, byte[] headerBytes, byte[] payloadBytes)
        {
            var headerSegment = _urlEncoder.Encode(headerBytes);
            var payloadSegment = _urlEncoder.Encode(payloadBytes);

            var stringToSign = headerSegment + "." + payloadSegment;
            var bytesToSign = GetBytes(stringToSign);

            var signatureSegment = GetSignatureSegment(algorithm, key, bytesToSign);
            return stringToSign + "." + signatureSegment;
        }

#if NET8_0_OR_GREATER
        private static string EncodeWithSpans(IJwtAlgorithm algorithm, byte[] key, string headerJson, string payloadJson)
        {
            var headerByteCount = GetByteCount(headerJson);
            var payloadByteCount = GetByteCount(payloadJson);
            var stringToSignLength = JwtBase64UrlEncoder.GetEncodedLength(headerByteCount) + 1 + JwtBase64UrlEncoder.GetEncodedLength(payloadByteCount);
            var tokenBufferLength = stringToSignLength + 1 + JwtBase64UrlEncoder.GetEncodedLength(SpanAlgorithmExtensions.MaxStackSignatureSize);

            var json = ArrayPool<byte>.Shared.Rent(Math.Max(headerByteCount, payloadByteCount));
            byte[] token = null;
            try
            {
                token = ArrayPool<byte>.Shared.Rent(tokenBufferLength);
                var length = JwtBase64UrlEncoder.Encode(json.AsSpan(0, GetBytes(headerJson, json)), token);
                token[length++] = (byte)'.';
                length += JwtBase64UrlEncoder.Encode(json.AsSpan(0, GetBytes(payloadJson, json)), token.AsSpan(length));

                var bytesToSign = token.AsSpan(0, length);
                Span<byte> signatureBuffer = stackalloc byte[SpanAlgorithmExtensions.MaxStackSignatureSize];
                var signature = algorithm is NoneAlgorithm ?
                    ReadOnlySpan<byte>.Empty :
                    ((ISpanAlgorithm)algorithm).Sign(key, bytesToSign, signatureBuffer);

                var tokenLength = length + 1 + JwtBase64UrlEncoder.GetEncodedLength(signature.Length);
                if (tokenLength > token.Length)
                {
                    var larger = ArrayPool<byte>.Shared.Rent(tokenLength);
                    bytesToSign.CopyTo(larger);
                    ArrayPool<byte>.Shared.Return(token, clearArray: true);
                    token = larger;
                }

                token[length++] = (byte)'.';
                length += JwtBase64UrlEncoder.Encode(signature, token.AsSpan(length));
                return GetString(token.AsSpan(0, length));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(json, clearArray: true);
                if (token is not null)
                    ArrayPool<byte>.Shared.Return(token, clearArray: true);
            }
        }
#endif

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