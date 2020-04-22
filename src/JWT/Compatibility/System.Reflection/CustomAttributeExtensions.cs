#if NET35 || NET40
namespace System.Reflection
{
    internal static class CustomAttributeExtensions
    {
        public static T GetCustomAttribute<T>(this MemberInfo element)
            where T : Attribute =>
            (T)Attribute.GetCustomAttribute(element, typeof(T));
    }
}
#endif
