using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class SerializerTests
    {
        [TestMethod]
        public void Serializer_Should_Use_Correct_Default()
        {
            var serializer = new DefaultJsonSerializerFactory().Create();
            var dotnetVersion = GetRunningDotnetVersion();

            if (String.Equals(dotnetVersion, ".NETFramework,Version=v4.6.2", StringComparison.OrdinalIgnoreCase) || dotnetVersion.StartsWith(".NETCoreApp"))
            {
                Assert.AreEqual("SystemTextSerializer", defaultSerializerClass);
            }
            else if (String.Equals(dotnetVersion, ".NETFramework,Version=v4.6.1", StringComparison.OrdinalIgnoreCase))
            {
                Assert.AreEqual("JsonNetSerializer", defaultSerializerClass);
            }
            else
            {
                Assert.Fail($"Unrecognized dotnet version {dotnetVersion}");
            }
        }

        /// <summary>
        /// Copied from: https://stackoverflow.com/a/49754978
        /// </summary>
        /// <returns>The running dotnet version.</returns>
        private string GetRunningDotnetVersion() =>
            Assembly.GetExecutingAssembly()
                    .GetCustomAttributes<TargetFrameworkAttribute>()
                    .SingleOrDefault()
                   ?.FrameworkName;
    }
}
