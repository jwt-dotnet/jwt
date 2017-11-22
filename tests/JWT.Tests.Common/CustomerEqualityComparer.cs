using System;
using System.Collections.Generic;

namespace JWT.Tests.Common
{
    public sealed class CustomerEqualityComparer : IEqualityComparer<Customer>
    {
        public bool Equals(Customer x, Customer y)
        {
            return x.Age == y.Age && String.Equals(x.FirstName, y.FirstName, StringComparison.Ordinal);
        }

        public int GetHashCode(Customer obj)
        {
            return obj.Age.GetHashCode() ^ obj.FirstName?.GetHashCode() ?? 0;
        }
    }
}