using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class DefaultJsonSerializerFactoryTests
    {
        [TestMethod]
        public void Create_Should_Return_Correct_Serializer_Per_Runtime_Version()
        {
            var serializer = CreateSerializer();
            var defaultSerializerClass = serializer.GetType().Name;
            var dotNetVersion = GetDotNetVersion();            

            if (String.Equals(dotNetVersion, ".NETFramework,Version=v4.6.2", StringComparison.OrdinalIgnoreCase) || dotNetVersion.StartsWith(".NETCoreApp"))
            {
                Assert.AreEqual("SystemTextSerializer", defaultSerializerClass);
            }
            else if (String.Equals(dotNetVersion, ".NETFramework,Version=v4.6.1", StringComparison.OrdinalIgnoreCase))
            {
                Assert.AreEqual("JsonNetSerializer", defaultSerializerClass);
            }
            else
            {
                Assert.Fail($"Unrecognized dotnet version {dotNetVersion}");
            }
        }
        
        private static IJsonSerializer CreateSerializer() =>
           new DefaultJsonSerializerFactory().Create();

        private string GetDotNetVersion() =>
            Assembly.GetExecutingAssembly()
                    .GetCustomAttributes(typeof(TargetFrameworkAttribute), false)
                    .Cast<TargetFrameworkAttribute>()
                    .Single()
                   ?.FrameworkName;
    }
}
