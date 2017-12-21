using System;
using JWT.Algorithms;
using JWT.Builder.Internal;
using JWT.Serializers;

namespace JWT.Builder
{
    /// <summary>
    /// Build and decode JWT with Fluent API.
    /// </summary>
    public class JwtBuilder
    {
        private readonly JwtData _jwt = new JwtData();

        private IJsonSerializer _serializer = new JsonNetSerializer();
        private IBase64UrlEncoder _urlEncoder = new JwtBase64UrlEncoder();
        private IJwtAlgorithm _algorithm;
        private IDateTimeProvider _dateTimeProvider = new UtcDateTimeProvider();
        private IJwtValidator _validator;
        private bool _verify;
        private string _secret;

        /// <summary>
        /// Add header to the JWT.
        /// </summary>
        /// <param name="name">Well-known header name.</param>
        /// <param name="value">The value you want give to the header.</param>
        /// <returns>The current builder instance</returns>
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
        /// <returns>The current builder instance</returns>
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
        /// <returns>The current builder instance</returns>
        public JwtBuilder AddClaim(string name, string value) => AddClaim(name, (object)value);

        /// <summary>
        /// Adds well-known claim to the JWT.
        /// </summary>
        /// <param name="name">Well-known claim name</param>
        /// <param name="value">Claim value</param>
        /// <returns>The current builder instance</returns>
        public JwtBuilder AddClaim(ClaimName name, string value) => AddClaim(name.GetPublicClaimName(), value);

        /// <summary>
        /// Sets JWT serializer.
        /// </summary>
        /// <remarks>
        /// If not set then default <see cref="JsonNetSerializer" /> will be used.
        /// </remarks>
        /// <returns>The current builder instance</returns>
        public JwtBuilder SetSerializer(IJsonSerializer serializer)
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
        /// <returns>The current builder instance</returns>
        public JwtBuilder SetDateTimeProvider(IDateTimeProvider provider)
        {
            _dateTimeProvider = provider;
            return this;
        }

        /// <summary>
        /// Sets JWT validator.
        /// </summary>
        /// <remarks>
        /// Required to decode with verification.
        /// </remarks>
        /// <returns>The current builder instance</returns>        
        public JwtBuilder SetValidator(IJwtValidator validator)
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
        /// <returns>The current builder instance</returns>
        public JwtBuilder SetUrlEncoder(IBase64UrlEncoder urlEncoder)
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
        /// <returns>The current builder instance</returns>
        public JwtBuilder SetAlgorithm(IJwtAlgorithm algorithm)
        {
            _algorithm = algorithm;
            return this;
        }

        /// <summary>
        /// Sets certificate secret.
        /// </summary>
        /// <remarks>
        /// Required to create new token that uses an asymmetric algorithm such as <seealso cref="RS256Algorithm" />.
        /// </remarks>
        /// <returns>The current builder instance</returns>
        public JwtBuilder SetSecret(string secret)
        {
            _secret = secret;
            return this;
        }

        /// <summary>
        /// Instructs to do verify the JWT signature.
        /// </summary>
        /// <returns>The current builder instance</returns>
        public JwtBuilder MustVerifySignature() => SetVerifySignature(true);

        /// <summary>
        /// Instructs to do not verify the JWT signature.
        /// </summary>
        /// <returns>The current builder instance</returns>
        public JwtBuilder DoNotVerifySignature() => SetVerifySignature(false);

        /// <summary>
        /// Instructs whether to verify the JWT signature.
        /// </summary>
        /// <returns>The current builder instance</returns>
        public JwtBuilder SetVerifySignature(bool verify)
        {
            _verify = verify;
            return this;
        }

        /// <summary>
        /// Builds a token using the supplied dependencies.
        /// </summary>
        /// <returns>The generated JWT.</returns>
        /// <exception cref="InvalidOperationException">Thrown if either of: algorithm, serializer, encoder, secret is null.</exception>
        public string Build()
        {
            if (!CanBuild())
            {
                throw new InvalidOperationException("Can't build a token. Check if you have call all of the followng methods:\r\n" +
                                                    $"-{nameof(SetAlgorithm)}\r\n" +
                                                    $"-{nameof(SetSerializer)}\r\n" +
                                                    $"-{nameof(SetUrlEncoder)}\r\n" +
                                                    $"-{nameof(SetSecret)}");
            }
            var encoder = new JwtEncoder(_algorithm, _serializer, _urlEncoder);
            return encoder.Encode(_jwt.Payload, _secret);
        }

        /// <summary>
        /// Decodes a token using the supplied dependencies.
        /// </summary>
        /// <returns>The JSON payload</returns>
        public string Decode(string token)
        {
            TryCreateValidator();
            if (!CanDecode())
            {
                throw new Exception("Can't decode a token. Check if you have call all of the followng methods:\r\n" +
                                    $"-{nameof(SetSerializer)}\r\n" +
                                    $"-{nameof(SetUrlEncoder)}\r\n" +
                                    $"-{nameof(SetDateTimeProvider)}\r\n" +
                                    $"-{nameof(SetValidator)}\r\n" +
                                    $"If you called {nameof(MustVerifySignature)} you must also call SetSecret.");

            }
            var decoder = new JwtDecoder(_serializer, _validator, _urlEncoder);
            return _verify ? decoder.Decode(token, _secret, _verify) : decoder.Decode(token);
        }

        /// <summary>
        /// Decodes a token with the decode information you pushed in the buider.
        /// </summary>
        /// <param name="token">The JWT you want to extract</param>
        /// <returns>The payload converted to <see cref="T" /></returns>
        public T Decode<T>(string token)
        {
            TryCreateValidator();
            if (!CanDecode())
            {
                throw new Exception("Can't decode a token. Check if you have call all of the followng methods:\r\n" +
                                    $"-{nameof(SetSerializer)}\r\n" +
                                    $"-{nameof(SetUrlEncoder)}\r\n" +
                                    $"-{nameof(SetDateTimeProvider)}\r\n" +
                                    $"-{nameof(SetValidator)}\r\n" +
                                    $"If you called {nameof(MustVerifySignature)} you must also call SetSecret"
                );

            }
            var decoder = new JwtDecoder(_serializer, _validator, _urlEncoder);
            return decoder.DecodeToObject<T>(token, _secret, _verify);
        }

        /// <summary>
        /// Tries to create a validator is not a custom validator set.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if either of: serializer, dateTimeProvider is null.</exception>
        private void TryCreateValidator()
        {
            if (_serializer == null || _dateTimeProvider == null)
                throw new InvalidOperationException("Can't create a validator. Please call SetSerializer and SetDateTimeProvider");

            if (_validator == null)
                _validator = new JwtValidator(_serializer, _dateTimeProvider);
        }

        /// <summary>
        /// Checks whether enought information was supplied to build a new token.
        /// </summary>
        private bool CanBuild()
        {
            return _algorithm != null &&
                   _serializer != null &&
                   _urlEncoder != null &&
                   _jwt.Payload != null &&
                   _secret != null &&
                   _secret.Length > 0;
        }

        /// <summary>
        /// Checks whether enought information was supplied to decode a token.
        /// </summary>
        private bool CanDecode()
        {
            if (_serializer != null &&
                _dateTimeProvider != null &&
                _validator != null &&
                _urlEncoder != null
            )
            {
                return !_verify || _verify && !String.IsNullOrEmpty(_secret);
            }
            return false;
        }
    }
}