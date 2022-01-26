using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class TargetFrameworkTests
    {
        [TestMethod]
#if NETSTANDARD2_0 || NETCOREAPP3_1
        [ExpectedException(typeof(System.InvalidOperationException))]
#endif
        public void Build_Must_Fail_When_TargetFramework_Is_Incorrect()
        {
#if NETSTANDARD2_0 || NETCOREAPP3_1
            throw new System.InvalidOperationException();
#endif
        }
    }
}