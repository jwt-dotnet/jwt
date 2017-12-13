using System;
using System.Collections.Generic;
using System.Linq;

namespace JWT.Tests.Common.Internal
{
    public sealed class DictionaryEqualityComparer : IEqualityComparer<IDictionary<string, object>>
    {
        public bool Equals(IDictionary<string, object> left, IDictionary<string, object> right)
        {
            return Enumerable.Zip(left, right, (l, r) => Equals(l, r)).All(b => b);
        }

        private static bool Equals(KeyValuePair<string, object> x, KeyValuePair<string, object> y)
        {
            return String.Equals(x.Key, y.Key, StringComparison.Ordinal) &&
                   String.Equals(x.Value?.ToString(), y.Value?.ToString(), StringComparison.Ordinal);
        }

        public int GetHashCode(IDictionary<string, object> obj)
        {
            return obj.GetHashCode();
        }
    }
}