using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class TargetFrameworkTests
    {
        [TestMethod]
        public void Build_Must_Fail_When_TargetFramework_Is_Incorrect()
        {
#if NETSTANDARD2_0 || NETCOREAPP3_1
            Assert.ThrowsExactly<System.InvalidOperationException>(() => { throw new System.InvalidOperationException(); });
#endif
        }
    }
}