using System.Collections.Generic;
using System.Linq;
using JWT.Serializers;

namespace JWT.Jwk
{
    public class JwtWebKeysCollection : IJwtWebKeysCollection
    {
        private readonly Dictionary<string, JwtWebKey> _keys;

        public JwtWebKeysCollection(IEnumerable<JwtWebKey> keys) => _keys = keys.ToDictionary(x => x.KeyId);

        public JwtWebKeysCollection(JwtWebKeySet keySet) : this(keySet.Keys)
        {   
        }

        public JwtWebKeysCollection(string keySet, IJsonSerializer serializer)
            : this(serializer.Deserialize<JwtWebKeySet>(keySet))
        {   
        }

        public JwtWebKeysCollection(string keySet, IJsonSerializerFactory jsonSerializerFactory)
            : this(keySet, jsonSerializerFactory.Create())
        {   
        }

        public JwtWebKey Find(string keyId) => _keys.TryGetValue(keyId, out var key) ? key : null;
    }
}