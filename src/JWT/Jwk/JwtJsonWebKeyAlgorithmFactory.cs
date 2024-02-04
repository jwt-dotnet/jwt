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
            var publicKey = CreateRSAPublicKey();

            var privateKey = CreateRSAPrivateKey();

            var algorithmFactory = privateKey == null
                ? new RSAlgorithmFactory(publicKey)
                : new RSAlgorithmFactory(publicKey, privateKey);

            return algorithmFactory.Create(context);
        }

        private IJwtAlgorithm CreateECDSAAlgorithm(JwtDecoderContext context)
        {
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
            var parameters = new ECParameters
            {
                Curve = GetEllipticCurve(),
                Q = new ECPoint
                {
                    X = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.EllipticCurveX),
                    Y = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.EllipticCurveY)
                },
                D = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.D)
            };

            var key = ECDsa.Create(parameters);

            var algorithmFactory = parameters.D == null
                ? new ECDSAAlgorithmFactory(key)
                : new ECDSAAlgorithmFactory(key, key);
#else
            // will throw NotImplementedException on algorithmFactory.Create invocation. ECDSA algorithms are implemented for .NET Standard 2.0 or higher
            var algorithmFactory = new ECDSAAlgorithmFactory();
#endif

            return algorithmFactory.Create(context);
        }

        private IJwtAlgorithm CreateHMACSHAAlgorithm(JwtDecoderContext context)
        {
            var key = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.SymmetricKey);

            var algorithmFactory = new HMACSHAAlgorithmFactory(key);

            return algorithmFactory.Create(context);
        }

        private RSA CreateRSAPublicKey()
        {
            var rsaParameters = new RSAParameters
            {
                Modulus = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.Modulus),
                Exponent = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.Exponent)
            };

            var key = RSA.Create();

            key.ImportParameters(rsaParameters);

            return key;
        }

        private RSA CreateRSAPrivateKey()
        {
            var firstPrimeFactor = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.FirstPrimeFactor);

            if (firstPrimeFactor == null)
                return null;

            var rsaParameters = new RSAParameters
            {
                Modulus = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.Modulus),
                Exponent = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.Exponent),
                P = firstPrimeFactor,
                Q = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.SecondPrimeFactor),
                D = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.D),
                DP = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.FirstFactorCRTExponent),
                DQ = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.SecondFactorCRTExponent),
                InverseQ = JwtWebKeyPropertyValuesEncoder.Base64UrlDecode(_key.FirstCRTCoefficient)
            };

            var key = RSA.Create();

            key.ImportParameters(rsaParameters);

            return key;
        }

#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        private ECCurve GetEllipticCurve()
        {
            switch (_key.EllipticCurveType)
            {
                case "P-256":
                    return ECCurve.NamedCurves.nistP256;

                case "P-384":
                    return ECCurve.NamedCurves.nistP384;

                case "P-521":
                    return ECCurve.NamedCurves.nistP521;

                default:
                    throw new InvalidJsonWebKeyEllipticCurveTypeException(_key.EllipticCurveType);
            }
        }
#endif
    }
}