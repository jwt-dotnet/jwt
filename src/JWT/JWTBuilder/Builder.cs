using System;
using JWT.JwtBuilder.Helpers;
using JWT.JwtBuilder.Enums;
using JWT.JwtBuilder.Models;
using JWT.Serializers;

namespace JWT.JwtBuilder
{
    /// <summary>
    /// Build and decode JWT with Fluent API.
    /// </summary>
    public class Builder
    {
        private readonly JwtData _jwt = new JwtData();

        private IJsonSerializer _serializer = new JsonNetSerializer();
        private IBase64UrlEncoder _urlEncoder = new JwtBase64UrlEncoder();
        private IJwtAlgorithm _algorithm;
        private IDateTimeProvider _utcProvieder = new UtcDateTimeProvider();
        private IJwtValidTor _validTor;
        private bool _verify;
        private string _secret;

        /// <summary>
        /// Here you can add headers to your JWT.
        /// TODO: this currently not working, because the JWT project not allow to set a header from the outside.
        /// </summary>
        /// <param name="name">Set the header-name. You can only use the defined headers!</param>
        /// <param name="value">The value you want give to the header.</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddHeader(HeaderName name, string value)
        {
            _jwt.Header.Add(name.GetHeaderName(), value);
            return this;
        }

        /// <summary>
        /// Add any claim you want to the JWT
        /// </summary>
        /// <param name="name">Your name of the Claim.</param>
        /// <param name="value">Your value of the Claim. It will be parse to JSON.</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddClaim(string name, object value)
        {
            _jwt.Payload.Add(name, value);
            return this;
        }

        /// <summary>
        /// Add string claims to the JWT payload.
        /// </summary>
        /// <param name="name">Your name of the Claim.</param>
        /// <param name="value">Your value of the claim as String.</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddClaim(string name, string value) => AddClaim(name, (object)value);

        /// <summary>
        /// Add public claims to the JWT payload.
        /// </summary>
        /// <param name="names">The name of the public claim you want set</param>
        /// <param name="value">The string-value for the public claim</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddClaim(PublicClaimsNames names, string value) => AddClaim(names.GetPublicClaimName(), value);

        /// <summary>
        /// Set a custom Serializier. If you don't set this it will be <see cref="JsonNetSerializer" /> use.
        /// </summary>
        /// <param name="serializer">The serializier instance you want use.</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetSerializer(IJsonSerializer serializer)
        {
            _serializer = serializer;
            return this;
        }

        /// <summary>
        /// Set a time provieder to get the time reference.!--
        /// If you don't call this the builder will use <see cref="UtcDateTimeProvider"/>
        /// </summary>
        /// <param name="provider">Zou custom provider you want use.</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetTimeProvider(IDateTimeProvider provider)
        {
            _utcProvieder = provider;
            return this;
        }

        /// <summary>
        /// Set the validTor. This is requierd for decode with verification!
        /// </summary>
        /// <param name="validTor">Your custom validTor</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetValidTor(IJwtValidTor validTor)
        {
            _validTor = validTor;
            return this;
        }

        /// <summary>
        /// Set a custom URL encoder.
        /// If you don't call this it will be use <see cref="JwtBase64UrlEncoder"/>
        /// </summary>
        /// <param name="urlEncoder">your custom encoder</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetUrlEncoder(IBase64UrlEncoder urlEncoder)
        {
            _urlEncoder = urlEncoder;
            return this;
        }

        /// <summary>
        /// Set a algorithm. This is requierd if you want create a new Token!
        /// </summary>
        /// <param name="algorithm">your alogrithm to sign the JWT.</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetAlgorithm(IJwtAlgorithm algorithm)
        {
            _algorithm = algorithm;
            return this;
        }

        /// <summary>
        /// Set a secret. This is requiered to build a new Token and to verify a token while decoding.
        /// </summary>
        /// <param name="secret">You secret to sign the token</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetSecret(string secret)
        {
            _secret = secret;
            return this;
        }

        /// <summary>
        /// Tell the Decoder to check if the token is trusted!
        /// </summary>
        /// <returns>The current builder-instance</returns>
        public Builder MustVerify()
        {
            _verify = true;
            return this;
        }

        /// <summary>
        /// Tell the Decoder to not check the token. This is default!
        /// </summary>
        /// <returns>The current builder-instance</returns>
        public Builder NotVerify()
        {
            _verify = false;
            return this;
        }

        /// <summary>
        /// Build the token from the Information that this instance of <see cref="Builder"/> have.
        /// </summary>
        /// <returns>The JWT String.</returns>
        public string Build()
        {
            if (!CanBuild())
            {
                throw new Exception("Can't build a Token. Check if you have call all of this: \n\r" +
                                    "- SetAlgorithm \n\r" +
                                    "- SetSerializer \n\r" +
                                    "- SetUrlEncoder \n\r" +
                                    "- SetSecret \n\r");
            }
            var encoder = new JwtEncoder(_algorithm, _serializer, _urlEncoder);
            return encoder.Encode(_jwt.Payload, _secret);
        }

        /// <summary>
        /// Decode a token with the decode-information you pushed in the buider.
        /// </summary>
        /// <param name="token">the JWT you want to extract</param>
        /// <returns>return the json payload</returns>
        public string Decode(string token)
        {
            TryToCreateAValidTor();
            if (!CanDecode())
            {
                throw new Exception("Can't build a Token. Check if you have call all of this: \n\r" +
                                    "- SetSerializer \n\r" +
                                    "- SetUrlEncoder \n\r" +
                                    "- SetTimeProvider \n\r" +
                                    "- SetValidTor \n\r" +
                                    "If you called MustVerify you must also call SetSecret"
                );

            }
            var decoder = new JwtDecoder(_serializer, _validTor, _urlEncoder);
            if (_verify == false)
            {
                return decoder.Decode(token);
            }
            return decoder.Decode(token, _secret, _verify);
        }

        /// <summary>
        /// Decode a token with the decode-information you pushed in the buider.
        /// </summary>
        /// <param name="token">the JWT you want to Extract</param>
        /// <returns>The payload converted to <see cref="T" /></returns>
        public T Decode<T>(string token)
        {
            TryToCreateAValidTor();
            if (!CanDecode())
            {
                throw new Exception("Can't build a Token. Check if you have call all of this: \n\r" +
                                    "- SetSerializer \n\r" +
                                    "- SetUrlEncoder \n\r" +
                                    "- SetTimeProvider \n\r" +
                                    "- SetValidTor \n\r" +
                                    "If you called MustVerify you must also call SetSecret"
                );

            }
            var decoder = new JwtDecoder(_serializer, _validTor, _urlEncoder);
            return decoder.DecodeToObject<T>(token, _secret, _verify);
        }

        /// <summary>
        /// Try to create a validTor is not a custom validTor set.
        /// <exception cref="Exception">Thrown if the <see cref="_serializer"/> or the <see cref="_utcProvieder"/> are null.</exception>
        /// </summary>
        private void TryToCreateAValidTor()
        {
            if (_serializer == null || _utcProvieder == null)
            {
                throw new Exception("Can't create a ValidTor. Please call SetSerializer and SetTimeProvider");
            }
            if (_validTor == null)
            {
                _validTor = new JwtValidTor(_serializer, _utcProvieder);
            }
        }

        /// <summary>
        /// Check if we have enaught information to build a new Token.
        /// </summary>
        /// <returns>Returns true if all requierd information are there to create a token.</returns>
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
        /// Check if we have enaught informations to decode a token.
        /// </summary>
        /// <returns>Returns ture if all requiered informations are there to create a token.</returns>
        private bool CanDecode()
        {
            if (_serializer != null &&
                _utcProvieder != null &&
                _validTor != null &&
                _urlEncoder != null
            )
            {
                return !_verify || _verify && !String.IsNullOrEmpty(_secret);
            }
            return false;
        }
    }
}