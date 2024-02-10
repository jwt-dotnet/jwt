using System;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;

namespace JWT.Jwk
{
    public sealed class JwtJsonWebKeySetAlgorithmFactory : IAlgorithmFactory
    {
        private readonly JwtWebKeysCollection _webKeysCollection;

        public JwtJsonWebKeySetAlgorithmFactory(JwtWebKeysCollection webKeysCollection)
        {
            _webKeysCollection = webKeysCollection;
        }

        public JwtJsonWebKeySetAlgorithmFactory(Func<JwtWebKeysCollection> getJsonWebKeys)
        {
            _webKeysCollection = getJsonWebKeys();
        }

        public JwtJsonWebKeySetAlgorithmFactory(IJwtWebKeysCollectionFactory webKeysCollectionFactory)
        {
            _webKeysCollection = webKeysCollectionFactory.CreateKeys();
        }

        public JwtJsonWebKeySetAlgorithmFactory(string keySet, IJsonSerializer serializer)
        {
            _webKeysCollection = new JwtWebKeysCollection(keySet, serializer);
        }

        public JwtJsonWebKeySetAlgorithmFactory(string keySet, IJsonSerializerFactory jsonSerializerFactory)
        {
            _webKeysCollection = new JwtWebKeysCollection(keySet, jsonSerializerFactory);
        }

        public IJwtAlgorithm Create(JwtDecoderContext context)
        {
            if (string.IsNullOrEmpty(context.Header.KeyId))
                throw new SignatureVerificationException("The key id is missing in the token header");

            var key = _webKeysCollection.Find(context.Header.KeyId);

            if (key == null)
                throw new SignatureVerificationException("The key id is not presented in the JSON Web key set");

            var algorithmFactory = new JwtJsonWebKeyAlgorithmFactory(key);

            return algorithmFactory.Create(context);
        }
    }
}