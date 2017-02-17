using System;
using JWT.Algorithms;

namespace JWT
{
    public class AlgorithmFactory
    {
        public IAlgorithm Create(string algorithmName)
        {
            switch (algorithmName)
            {
                case "HS256":
                    return new HMACSHA256Algorithm();
                case "HS384":
                    return new HMACSHA384Algorithm();
                case "HS512":
                    return new HMACSHA512Algorithm();
                default:
                    throw new InvalidOperationException("Algorithm not supported.");
            }
        }
    }
}