using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class TargetFrameworkTests
    {
        [TestMethod]
#if NET35
        [ExpectedException(typeof(System.InvalidOperationException))]
#endif
        public void Build_Must_Fail_When_TargetFramework_Is_Incorrect()
        {
#if NET35
            throw new System.InvalidOperationException();
#endif
        }
    }
}