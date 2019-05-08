using System;
using System.Linq;
using JWT.Algorithms;
using JWT.Serializers;

using static JWT.Internal.EncodingHelper;

namespace JWT.Builder
{
    /// <summary>
    /// Build and decode JWT with Fluent API.
    /// </summary>
    public sealed class JwtBuilder
    {
        private readonly JwtData _jwt = new JwtData();

        private IJwtEncoder _encoder;
        private IJwtDecoder _decoder;
        private IJwtValidator _validator;

        private IJsonSerializer _serializer = new JsonNetSerializer();
        private IBase64UrlEncoder _urlEncoder = new JwtBase64UrlEncoder();
        private IDateTimeProvider _dateTimeProvider = new UtcDateTimeProvider();

        private IJwtAlgorithm _algorithm;
        private byte[][] _secrets;
        private bool _verify;

        /// <summary>
        /// Add header to the JWT.
        /// </summary>
        /// <param name="name">Well-known header name</param>
        /// <param name="value">The value you want give to the header</param>
        /// <returns>Current builder instance</returns>
        public JwtBuilder AddHeader(HeaderName name, string value)
        {
            _jwt.Header.Add(name.GetHeaderName(), value);
            return this;
        }

        /// <summary>
        /// Adds claim to the JWT.
        /// </summary>
        /// <param name="name">Claim name</param>
        /// <param name="value">Claim value</param>
        /// <returns>Current builder instance</returns>
        public JwtBuilder AddClaim(string name, object value)
        {
            _jwt.Payload.Add(name, value);
            return this;
        }

        /// <summary>
        /// Add string claim to the JWT.
        /// </summary>
        /// <param name="name">Claim name</param>
        /// <param name="value">Claim value</param>
        /// <returns>Current builder instance</returns>
        public JwtBuilder AddClaim(string name, string value) =>
            AddClaim(name, (object)value);

        /// <summary>
        /// Adds well-known claim to the JWT.
        /// </summary>
        /// <param name="name">Well-known claim name</param>
        /// <param name="value">Claim value</param>
        /// <returns>Current builder instance</returns>
        public JwtBuilder AddClaim(ClaimName name, string value) =>
            AddClaim(name.GetPublicClaimName(), value);

        /// <summary>
        /// Sets JWT serializer.
        /// </summary>
        /// <remarks>
        /// If not set then default <see cref="JsonNetSerializer" /> will be used.
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithSerializer(IJsonSerializer serializer)
        {
            _serializer = serializer;
            return this;
        }

        /// <summary>
        /// Sets custom datetime provider.
        /// </summary>
        /// <remarks>
        /// If not set then default <see cref="UtcDateTimeProvider" /> will be used.
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithDateTimeProvider(IDateTimeProvider provider)
        {
            _dateTimeProvider = provider;
            return this;
        }

        /// <summary>
        /// Sets JWT encoder.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithEncoder(IJwtEncoder encoder)
        {
            _encoder = encoder;
            return this;
        }

        /// <summary>
        /// Sets JWT decoder.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithDecoder(IJwtDecoder decoder)
        {
            _decoder = decoder;
            return this;
        }

        /// <summary>
        /// Sets JWT validator.
        /// </summary>
        /// <remarks>
        /// Required to decode with verification.
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithValidator(IJwtValidator validator)
        {
            _validator = validator;
            return this;
        }

        /// <summary>
        /// Sets custom URL encoder.
        /// </summary>
        /// <remarks>
        /// If not set then default <see cref="JwtBase64UrlEncoder" /> will be used.
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithUrlEncoder(IBase64UrlEncoder urlEncoder)
        {
            _urlEncoder = urlEncoder;
            return this;
        }

        /// <summary>
        /// Sets JWT algorithm.
        /// </summary>
        /// <remarks>
        /// Required to create new token.
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithAlgorithm(IJwtAlgorithm algorithm)
        {
            _algorithm = algorithm;
            return this;
        }

        /// <summary>
        /// Sets certificate secret.
        /// </summary>
        /// <remarks>
        /// Required to create new token that uses an symmetric algorithm such as <seealso cref="RS256Algorithm" />
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithSecret(params string[] secrets)
        {
            _secrets = secrets.Select(s => GetBytes(s)).ToArray();
            return this;
        }

        /// <summary>
        /// Sets certificate secret.
        /// </summary>
        /// <remarks>
        /// Required to create new token that uses an symmetric algorithm such as <seealso cref="RS256Algorithm" />
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithSecret(params byte[][] secrets)
        {
            _secrets = secrets;
            return this;
        }

        /// <summary>
        /// Instructs to do verify the JWT signature.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder MustVerifySignature() =>
            WithVerifySignature(true);

        /// <summary>
        /// Instructs to do not verify the JWT signature.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder DoNotVerifySignature() =>
            WithVerifySignature(false);

        /// <summary>
        /// Instructs whether to verify the JWT signature.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithVerifySignature(bool verify)
        {
            _verify = verify;
            return this;
        }

        /// <summary>
        /// Builds a token using the supplied dependencies.
        /// </summary>
        /// <returns>The generated JWT</returns>
        /// <exception cref="InvalidOperationException">Thrown if either algorithm, serializer, encoder or secret is null</exception>
        public string Build()
        {
            if (_encoder is null)
                TryCreateEncoder();

            EnsureCanBuild();

            return _encoder.Encode(_jwt.Header, _jwt.Payload, _secrets[0]);
        }

        /// <summary>
        /// Decodes a token using the supplied dependencies.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <returns>The JSON payload</returns>
        public string Decode(string token)
        {
            if (_decoder is null)
                TryCreateDecoder();

            return _verify ? _decoder.Decode(token, _secrets, _verify) : _decoder.Decode(token);
        }

        /// <summary>
        /// Decodes a token using the supplied dependencies.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <returns>The payload converted to <see cref="T" /></returns>
        public T Decode<T>(string token)
        {
            if (_decoder is null)
                TryCreateDecoder();

            return _verify ? _decoder.DecodeToObject<T>(token, _secrets[0], _verify) : _decoder.DecodeToObject<T>(token);
        }

        private void TryCreateEncoder()
        {
            if (_algorithm is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtEncoder)}. Call {nameof(WithAlgorithm)}.");
            if (_serializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtEncoder)}. Call {nameof(WithSerializer)}");
            if (_urlEncoder is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtEncoder)}. Call {nameof(WithUrlEncoder)}.");

            _encoder = new JwtEncoder(_algorithm, _serializer, _urlEncoder);
        }

        private void TryCreateDecoder()
        {
            TryCreateValidator();

            if (_serializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithSerializer)}.");
            if (_validator is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithValidator)}.");
            if (_urlEncoder is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithUrlEncoder)}.");

            EnsureCanDecode();

            _decoder = new JwtDecoder(_serializer, _validator, _urlEncoder);
        }

        private void TryCreateValidator()
        {
            if (_validator != null)
                return;

            if (_serializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtValidator)}. Call {nameof(WithSerializer)}.");
            if (_dateTimeProvider is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtValidator)}. Call {nameof(WithDateTimeProvider)}.");

            _validator = new JwtValidator(_serializer, _dateTimeProvider);
        }

        private void EnsureCanBuild()
        {
            if (!CanBuild())
                throw new InvalidOperationException("Can't build a token. Check if you have call all of the followng methods:\r\n" +
                                                    $"-{nameof(WithAlgorithm)}" + Environment.NewLine +
                                                    $"-{nameof(WithSerializer)}" + Environment.NewLine +
                                                    $"-{nameof(WithUrlEncoder)}.");

            if (!HasOnlyOneSecret())
                throw new InvalidOperationException("You can't provide more than one secret to use for encoding.");
        }

        private void EnsureCanDecode()
        {
            if (!CanDecode())
                throw new InvalidOperationException("Can't decode a token. Check if you have call all of the following methods:" + Environment.NewLine +
                                                    $"-{nameof(WithSerializer)}" + Environment.NewLine +
                                                    $"-{nameof(WithValidator)}" + Environment.NewLine +
                                                    $"-{nameof(WithUrlEncoder)}.");
        }

        /// <summary>
        /// Checks whether enough dependencies were supplied to build a new token.
        /// </summary>
        private bool CanBuild() =>
            _algorithm != null &&
            _serializer != null &&
            _urlEncoder != null &&
            _jwt.Payload != null &&
            (_algorithm.IsAsymmetric || HasOnlyOneSecret());

        /// <summary>
        /// Checks whether enough dependencies were supplied to decode a token.
        /// </summary>
        private bool CanDecode()
        {
            if (_serializer != null &&
                _dateTimeProvider != null &&
                _urlEncoder != null)
            {
                return !_verify || (_algorithm?.IsAsymmetric ?? true) || HasSecrets();
            }

            return false;
        }

        /// <summary>
        /// Checks if any secret was supplied to use in token decoding
        /// </summary>
        private bool HasSecrets() =>
            _secrets != null && _secrets.Length > 0;

        /// <summary>
        /// Checks if there is only one secret was supplied for token encoding
        /// </summary>
        /// <returns></returns>
        private bool HasOnlyOneSecret() =>
            _secrets != null && _secrets.Length == 1;
    }
}