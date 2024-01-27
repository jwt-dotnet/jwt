using JWT.Jwk;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Jwk;

[TestClass]
public class JwtWebKeysCollectionTests
{
    [TestMethod]
    public void Should_Find_Json_Web_Key_By_KeyId()
    {
        var serializerFactory = new DefaultJsonSerializerFactory();

        var collection = new JwtWebKeysCollection(TestData.JsonWebKeySet, serializerFactory);

        var jwk = collection.Find(TestData.ServerRsaPublicThumbprint1);

        Assert.IsNotNull(jwk);
    }
}