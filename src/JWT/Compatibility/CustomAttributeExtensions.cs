#if NET35
namespace System.Reflection
{
    internal static class CustomAttributeExtensions
    {
        public static T GetCustomAttribute<T>(this MemberInfo element) where T : Attribute
        {
            return (T)Attribute.GetCustomAttribute(element, typeof(T));
        }
    }
}
#endif