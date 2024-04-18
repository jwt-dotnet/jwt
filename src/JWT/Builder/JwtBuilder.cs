using System;
using System.Linq;
using System.Reflection;
using JWT.Algorithms;
using JWT.Serializers;
using Newtonsoft.Json;

#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
using System.Text.Json.Serialization;
#endif

using static JWT.Internal.EncodingHelper;

namespace JWT.Builder
{
    /// <summary>
    /// Encode and decode JWT with Fluent API.
    /// </summary>
    public sealed class JwtBuilder
    {
        private readonly JwtData _jwt = new JwtData();

        private IJwtEncoder _encoder;
        private IJwtDecoder _decoder;
        private IJwtValidator _validator;

        private IJsonSerializerFactory _jsonSerializerFactory = new DefaultJsonSerializerFactory();
        
        private IBase64UrlEncoder _urlEncoder = new JwtBase64UrlEncoder();
        private IDateTimeProvider _dateTimeProvider = new UtcDateTimeProvider();
        private ValidationParameters _valParams = ValidationParameters.Default;

        private IJwtAlgorithm _algorithm;
        private IAlgorithmFactory _algFactory;
        private byte[][] _secrets;

        /// <summary>
        /// Creates a new instance of instance <see cref="JwtBuilder" />
        /// </summary>
        public static JwtBuilder Create() =>
            new JwtBuilder();

        /// <summary>
        /// Add header to the JWT.
        /// </summary>
        /// <param name="name">Well-known header name</param>
        /// <param name="value">The value you want give to the header</param>
        /// <returns>Current builder instance</returns>
        public JwtBuilder AddHeader(HeaderName name, object value)
        {
            _jwt.Header.Add(name.GetHeaderName(), value);
            return this;
        }

        /// <summary>
        /// Add header to the JWT.
        /// </summary>
        /// <remarks>This adds a non-standard header value.</remarks>
        /// <param name="name">Header name</param>
        /// <param name="value">The value you want give to the header</param>
        /// <returns>Current builder instance</returns>
        public JwtBuilder AddHeader(string name, object value)
        {
            _jwt.Header.Add(name, value);
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
        /// Sets JWT serializer.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithJsonSerializer(IJsonSerializer serializer) =>
            WithJsonSerializerFactory(new DelegateJsonSerializerFactory(serializer));

        /// <summary>
        /// Sets JWT serializer.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithJsonSerializer(Func<IJsonSerializer> factory) =>
            WithJsonSerializerFactory(new DelegateJsonSerializerFactory(factory));

        /// <summary>
        /// Sets JWT serializer factory.
        /// </summary>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithJsonSerializerFactory(IJsonSerializerFactory jsonSerializerFactory)
        {
            _jsonSerializerFactory = jsonSerializerFactory;
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
        /// Sets JWT algorithm factory.
        /// </summary>
        /// <returns>Current builder instance.</returns>
        public JwtBuilder WithAlgorithmFactory(IAlgorithmFactory algFactory)
        {
            _algFactory = algFactory;
            return this;
        }

        /// <summary>
        /// Sets JWT algorithm.
        /// </summary>
        /// <returns>Current builder instance.</returns>
        public JwtBuilder WithAlgorithm(IJwtAlgorithm algorithm)
        {
            _algorithm = algorithm;

            if (_algorithm is NoneAlgorithm)
                _valParams.ValidateSignature = false;

            return this;
        }

        /// <summary>
        /// Sets secrets.
        /// </summary>
        /// <remarks>
        /// Required to create a new token that uses an symmetric algorithm such as <seealso cref="RS256Algorithm" />
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithSecret(params string[] secrets)
        {
            _secrets = secrets.Select(s => GetBytes(s)).ToArray();
            return this;
        }

        /// <summary>
        /// Sets secrets.
        /// </summary>
        /// <remarks>
        /// Required to create a new token that uses an symmetric algorithm such as <seealso cref="RS256Algorithm" />
        /// </remarks>
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithSecret(params byte[][] secrets)
        {
            _secrets = secrets;
            return this;
        }

        /// <summary>
        /// Instructs to verify the JWT signature.
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
        public JwtBuilder WithVerifySignature(bool verify) =>
            WithValidationParameters(p => p.ValidateSignature = verify);

        /// <summary>
        /// Sets the JWT signature validation parameters.
        /// </summary>
        /// <param name="valParams">Parameters to be used for validation</param>
        /// <exception cref="ArgumentNullException" />
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithValidationParameters(ValidationParameters valParams)
        {
            if (valParams.ValidateSignature && _algorithm is NoneAlgorithm)
                throw new InvalidOperationException("Verify signature is not allowed for algorithm None");

            _valParams = valParams;

            return this;
        }

        /// <summary>
        /// Sets the JWT signature validation parameters.
        /// </summary>
        /// <param name="action">Delegate to produce parameters to be used for validation</param>
        /// <exception cref="ArgumentNullException" />
        /// <returns>Current builder instance</returns>
        public JwtBuilder WithValidationParameters(Action<ValidationParameters> action) =>
            WithValidationParameters(_valParams.With(action));

        /// <summary>
        /// Encodes a token using the supplied dependencies.
        /// </summary>
        /// <returns>The generated JWT</returns>
        /// <exception cref="InvalidOperationException" />
        /// <returns>Current builder instance</returns>
        public string Encode()
        {
            EnsureCanEncode();

            return _encoder.Encode(_jwt.Header, _jwt.Payload, _secrets?[0]);
        }

        public string Encode(object payload)
        {
            if (payload is null)
                throw new ArgumentNullException(nameof(payload));

            EnsureCanEncode();

            if (_jwt.Payload.Any())
            {
                throw new NotSupportedException("Supplying both key-value pairs and implicit payload is not supported.");
            }

            return _encoder.Encode(_jwt.Header, payload, _secrets?[0]);
        }

        /// <summary>
        /// Decodes a token using the supplied dependencies.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <returns>The JSON payload</returns>
        public string Decode(string token)
        {
            EnsureCanDecode();

            return _decoder.Decode(token, _secrets, _valParams.ValidateSignature);
        }

        /// <summary>
        /// Given a JWT, decodes it and return the header.
        /// </summary>
        /// <param name="token">The JWT</param>
        public string DecodeHeader(string token)
        {
            EnsureCanDecode();

            return _decoder.DecodeHeader(token);
        }

        /// <summary>
        /// Given a JWT, decodes it and return the header.
        /// </summary>
        /// <param name="token">The JWT</param>
        public T DecodeHeader<T>(string token)
        {
            EnsureCanDecodeHeader();

            return _decoder.DecodeHeader<T>(token);
        }

        public object Decode(string token, Type type)
        {
            EnsureCanDecode();

            return _decoder.DecodeToObject(type, token, _secrets, _valParams.ValidateSignature);
        }
        
        
        /// <summary>
        /// Decodes a token using the supplied dependencies.
        /// </summary>
        /// <param name="token">The JWT</param>
        public T Decode<T>(string token)
        {
            EnsureCanDecode();

            return _decoder.DecodeToObject<T>(token, _secrets, _valParams.ValidateSignature);
        }

        private void TryCreateEncoder()
        {
            if (_algorithm is null && _algFactory is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtEncoder)}. Call {nameof(WithAlgorithm)}.");

            var jsonSerializer = _jsonSerializerFactory.Create();
            if (jsonSerializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtEncoder)}. Call {nameof(WithJsonSerializer)}");
            if (_urlEncoder is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtEncoder)}. Call {nameof(WithUrlEncoder)}.");

            if (_algorithm is not null)
                _encoder = new JwtEncoder(_algorithm, jsonSerializer, _urlEncoder);
            else if (_algFactory is not null)
                _encoder = new JwtEncoder(_algFactory, jsonSerializer, _urlEncoder);
        }

        private void TryCreateDecoder()
        {
            TryCreateValidator();

            var jsonSerializer = _jsonSerializerFactory.Create();
            if (jsonSerializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithJsonSerializer)}.");
            if (_urlEncoder is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithUrlEncoder)}.");

            if (_algorithm is not null)
                _decoder = new JwtDecoder(jsonSerializer, _validator, _urlEncoder, _algorithm);
            else if (_algFactory is not null)
                _decoder = new JwtDecoder(jsonSerializer, _validator, _urlEncoder, _algFactory);
            else if (!_valParams.ValidateSignature)
                _decoder = new JwtDecoder(jsonSerializer, _urlEncoder);
        }

        private void TryCreateDecoderForHeader()
        {
            var jsonSerializer = _jsonSerializerFactory.Create();
            if (jsonSerializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithJsonSerializer)}.");
            if (_urlEncoder is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtDecoder)}. Call {nameof(WithUrlEncoder)}.");

            _decoder = new JwtDecoder(jsonSerializer, _urlEncoder);
        }

        private void TryCreateValidator()
        {
            if (_validator is not null)
                return;

            var jsonSerializer = _jsonSerializerFactory.Create();
            if (jsonSerializer is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtValidator)}. Call {nameof(WithJsonSerializer)}.");
            if (_dateTimeProvider is null)
                throw new InvalidOperationException($"Can't instantiate {nameof(JwtValidator)}. Call {nameof(WithDateTimeProvider)}.");

            _validator = new JwtValidator(jsonSerializer, _dateTimeProvider, _valParams);
        }

        private void EnsureCanEncode()
        {
            if (_encoder is null)
                TryCreateEncoder();

            if (!CanEncode())
            {
                throw new InvalidOperationException(
                    "Can't encode a token. Check if you have called all of the following methods:" + Environment.NewLine +
                    $"-{nameof(WithAlgorithm)}" + Environment.NewLine +
                    $"-{nameof(WithJsonSerializer)}" + Environment.NewLine +
                    $"-{nameof(WithUrlEncoder)}.");
            }
        }

        private void EnsureCanDecode()
        {
            if (_decoder is null)
                TryCreateDecoder();

            if (!CanDecode())
            {
                throw new InvalidOperationException(
                    "Can't decode a token. Check if you have called all of the following methods:" + Environment.NewLine +
                    $"-{nameof(WithJsonSerializer)}" + Environment.NewLine +
                    $"-{nameof(WithValidator)}" + Environment.NewLine +
                    $"-{nameof(WithUrlEncoder)}.");
            }
        }

        private void EnsureCanDecodeHeader()
        {
            if (_decoder is null)
                TryCreateDecoderForHeader();

            if (!CanDecodeHeader())
            {
                throw new InvalidOperationException(
                    "Can't decode a token header. Check if you have called all of the following methods:" + Environment.NewLine +
                    $"-{nameof(WithJsonSerializer)}" + Environment.NewLine +
                    $"-{nameof(WithUrlEncoder)}.");
            }
        }

        /// <summary>
        /// Checks whether enough dependencies were supplied to encode a new token.
        /// </summary>
        private bool CanEncode() =>
            (_algorithm is not null || _algFactory is not null) &&
            _jsonSerializerFactory is not null &&
            _urlEncoder is not null &&
            _jwt.Payload is not null;

        /// <summary>
        /// Checks whether enough dependencies were supplied to decode a token.
        /// </summary>
        private bool CanDecode()
        {
            if (_urlEncoder is null)
                return false;

            if (_valParams.ValidateSignature)
                return _validator is not null && (_algorithm is not null || _algFactory is not null);

            return true;
        }

        private bool CanDecodeHeader()
        {
            if (_urlEncoder is null)
                return false;

            return _jsonSerializerFactory is not null;
        }

        private string GetPropName(MemberInfo prop)
        {
            var jsonSerializer = _jsonSerializerFactory.Create();

            var customAttributes = prop.GetCustomAttributes(inherit: true);
            foreach (var attribute in customAttributes)
            {
                switch (jsonSerializer)
                {
                    case JsonNetSerializer:
                    {
                        if (attribute is JsonPropertyAttribute jsonNetProperty)
                        {
                            return jsonNetProperty.PropertyName;
                        }
                        break;
                    }
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
                    case SystemTextSerializer:
                    {
                        if (attribute is JsonPropertyNameAttribute stjProperty)
                        {
                            return stjProperty.Name;
                        }
                        break;
                    }
#endif
                    default:
                    {
                        return prop.Name;
                    }
                }
            }

            return prop.Name;
        }
    }
}
