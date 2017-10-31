using System;
using JWT.JWTBuilder.Enums;
using JWT.JWTBuilder.Helper;
using JWT.JWTBuilder.Models;
using JWT.Serializers;

namespace JWT.JWTBuilder
{
    /// <summary>
    /// Build an Decode JWT for with a Fluent-API.
    /// </summary>
    public class Builder
    {
        private JWTData jwt = new JWTData();
        private IJsonSerializer serializer = new JsonNetSerializer();
        private IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private IJwtAlgorithm algorithm;
        private IDateTimeProvider utcProvieder = new UtcDateTimeProvider();
        private IJwtValidator validator;
        private bool verify = false;
        private string secret = "";

        /// <summary>
        /// Here you can add headers to your JWT.
        /// TODO: this currently not working, because the JWT porject not allow to set a header from the outside...
        /// </summary>
        /// <param name="name">Set the header-name. You can only use the defined headers!</param>
        /// <param name="value">The value you want give to the header.</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddHeader(HeaderName name, string value)
        {
            this.jwt.Header.Add(name.GetHeaderName(), value);
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
            this.jwt.PayLoad.Add(name, value);
            return this;
        }
        /// <summary>
        /// Add string claims to the JWT payload.
        /// </summary>
        /// <param name="name">Your name of the Claim.</param>
        /// <param name="value">Your value of the claim as string.</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddClaim(string name, string value) => this.AddClaim(name, (object)value);
        /// <summary>
        /// Add public claims to the JWT payload.
        /// </summary>
        /// <param name="name">The name of the public claim you want set</param>
        /// <param name="value">The string-value for the public claim</param>
        /// <returns>The current builder-instance</returns>
        public Builder AddClaim(PublicClaimsNames names, string value) => this.AddClaim(names.GetPublicClaimName(), value);
        /// <summary>
        /// Set a custom Serializier. If you don't set this it will be <see cref="JsonNetSerializer" /> use.
        /// </summary>
        /// <param name="serializer">The serializier instance you want use.</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetSerializer(IJsonSerializer serializer)
        {
            this.serializer = serializer;
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
            this.utcProvieder = provider;
            return this;
        }
        /// <summary>
        /// Set the validator. This is requierd for decode with verification!
        /// </summary>
        /// <param name="validator">Your custom validator</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetValidator(IJwtValidator validator)
        {
            this.validator = validator;
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
            this.urlEncoder = urlEncoder;
            return this;
        }
        /// <summary>
        /// Set a algorithm. This is requierd if you want create a new Token!
        /// </summary>
        /// <param name="algorithm">your alogrithm to sign the JWT.</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetAlgorithm(IJwtAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            return this;
        }
        /// <summary>
        /// Set a secret. This is requiered to build a new Token and to verify a token while decoding.
        /// </summary>
        /// <param name="secret">You secret to sign the token</param>
        /// <returns>The current builder-instance</returns>
        public Builder SetSecret(string secret)
        {
            this.secret = secret;
            return this;
        }
        /// <summary>
        /// Tell the Decoder to check if the token is trusted!
        /// </summary>
        /// <returns>The current builder-instance</returns>
        public Builder MustVerify()
        {
            this.verify = true;
            return this;
        }
        /// <summary>
        /// Tell the Decoder to not check the token. This is default!
        /// </summary>
        /// <returns>The current builder-instance</returns>
        public Builder NotVerify()
        {
            this.verify = false;
            return this;
        }
        /// <summary>
        /// Build the token from the Information that this instance of <see cref="Builder"/> have.
        /// </summary>
        /// <returns>The JWT string.</returns>
        public string Build()
        {
            if (!canBuild())
            {
                throw new Exception("Can't build a Token. Check if you have call all of this: \n\r" +
                "- SetAlgorithm \n\r" +
                "- SetSerializer \n\r" +
                "- SetUrlEncoder \n\r" +
                "- SetSecret \n\r");
            }
            var encoder = new JwtEncoder(this.algorithm, this.serializer, this.urlEncoder);
            return encoder.Encode(this.jwt.PayLoad, secret);
        }

        /// <summary>
        /// Decode a token with the decode-information you pushed in the buider.
        /// </summary>
        /// <param name="token">the JWT you want to extract</param>
        /// <returns>return the json payload</returns>
        public string Decode(string token)
        {
            tryToCreateAValidator();
            if (!canDecode())
            {
                throw new Exception("Can't build a Token. Check if you have call all of this: \n\r" +
                "- SetSerializer \n\r" +
                "- SetUrlEncoder \n\r" +
                "- SetTimeProvider \n\r" +
                "- SetValidator \n\r" +
                "If you called MustVerify you must also call SetSecret"
                );

            }
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);
            return decoder.Decode(token, secret, verify);
        }
        /// <summary>
        /// Decode a token with the decode-information you pushed in the buider.
        /// </summary>
        /// <param name="token">the JWT you want to Extract</param>
        /// <returns>The payload converted to <see cref="T"/></returns>
        public T Decode<T>(string token)
        {
            tryToCreateAValidator();
            if (!canDecode())
            {
                throw new Exception("Can't build a Token. Check if you have call all of this: \n\r" +
                "- SetSerializer \n\r" +
                "- SetUrlEncoder \n\r" +
                "- SetTimeProvider \n\r" +
                "- SetValidator \n\r" +
                "If you called MustVerify you must also call SetSecret"
                );

            }
            var decoder = new JwtDecoder(serializer, validator, urlEncoder);
            return decoder.DecodeToObject<T>(token, secret, verify);
        }
        /// <summary>
        /// Try to create a validator is not a custom validator set.
        /// <exception cref="Exception">Thrown if the <see cref="serializer"/> or the <see cref="utcProvieder"/> are null.</exception
        /// </summary>
        private void tryToCreateAValidator()
        {
            if (serializer == null || utcProvieder == null)
            {
                throw new Exception("Can't create a Validator. Please call SetSerializer and SetTimeProvider");
            }
            if (validator == null)
            {
                validator = new JwtValidator(serializer, utcProvieder);
            }
        }
        /// <summary>
        /// Check if we have enaught information to build a new Token.
        /// </summary>
        /// <returns>Returns true if all requierd information are there to create a token.</returns>
        private bool canBuild()
        {
            if (
                algorithm != null &&
                serializer != null &&
                urlEncoder != null &&
                jwt.PayLoad != null &&
                secret != null &&
                secret.Length > 0)
            {
                return true;
            }
            return false;
        }
        /// <summary>
        /// Check if we have enaught informations to decode a token.
        /// </summary>
        /// <returns>Returns ture if all requiered informations are there to create a token.</returns>
        private bool canDecode()
        {
            if (serializer != null &&
            utcProvieder != null &&
            validator != null &&
            urlEncoder != null
            )
            {
                return (!verify || (verify && secret == null && secret.Length > 0));
            }
            return false;
        }

    }
}
