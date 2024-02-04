using System;
using System.Security.Cryptography;
using JWT.Algorithms;
using JWT.Exceptions;

namespace JWT.Jwk
{
    internal sealed class JwtJsonWebKeyAlgorithmFactory : IAlgorithmFactory
    {
        private readonly JwtWebKey _key;

        public JwtJsonWebKeyAlgorithmFactory(JwtWebKey key)
        {
            _key = key;
        }

        public IJwtAlgorithm Create(JwtDecoderContext context)
        {
            switch (_key.KeyType)
            {
                case "RSA":
                    return CreateRSAAlgorithm(context);

                case "EC":
                    return CreateECDSAAlgorithm(context);

                case "oct":
                    return CreateHMACSHAAlgorithm(context);

                default:
                    throw new InvalidJsonWebKeyTypeException(_key.KeyType);
            }
        }

        private IJwtAlgorithm CreateRSAAlgorithm(JwtDecoderContext context)
        {
            var rsaParameters = new RSAParameters
            {
                Modulus = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.Modulus),
                Exponent = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.Exponent)
            };

            var publicKey = RSA.Create();

            publicKey.ImportParameters(rsaParameters);

            var algorithmFactory = new RSAlgorithmFactory(publicKey);

            return algorithmFactory.Create(context);
        }

        private IJwtAlgorithm CreateECDSAAlgorithm(JwtDecoderContext context)
        {
            throw new NotImplementedException("TODO: implement me!");
        }

        private static IJwtAlgorithm CreateHMACSHAAlgorithm(JwtDecoderContext context)
        {
            var algorithmFactory = new HMACSHAAlgorithmFactory();

            return algorithmFactory.Create(context);
        }
    }
}