using System;
using System.Collections.Generic;
using System.Linq;

namespace Aegis.InjectionDetector
{
    public class InjectionDetector
    {
        private readonly Dictionary<string, string> _allowedFunctions = new Dictionary<string, string>
        {
            { "Add", "System.Collections.Generic.List`1[System.String].Add" },
            { "Insert", "System.Collections.Generic.List`1[System.String].Insert" },
            { "Append", "System.Text.StringBuilder.Append" },
            { "Format", "System.String.Format" }
        };

        public bool IsSafe(string input, string methodName)
        {
            if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(methodName))
                return true;

            var methodKey = methodName.ToLower();
            if (!_allowedFunctions.ContainsKey(methodKey))
                return false;

            var allowedMethod = _allowedFunctions[methodKey];
            var methodInfo = typeof(System.Reflection.MethodBase).GetMethod("GetParameters", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            var parameters = methodInfo.Invoke(null, new object[] { allowedMethod });

            if (parameters == null || !(parameters is System.Reflection.ParameterInfo[]))
                return false;

            var parameterInfos = (System.Reflection.ParameterInfo[])parameters;
            var isSafe = true;

            foreach (var param in parameterInfos)
            {
                var paramType = param.ParameterType;
                if (paramType.IsClass && !paramType.IsPrimitive && !paramType.IsEnum)
                {
                    var paramValue = param.GetValue(null);
                    if (paramValue != null && paramValue.ToString().Contains("<"))
                    {
                        isSafe = false;
                        break;
                    }
                }
            }

            return isSafe;
        }

        public static void Main()
        {
            var detector = new InjectionDetector();

            // Demo: Check if a string input is safe for a method
            Console.WriteLine("Testing injection detection...");

            var testInputs = new List<(string methodName, string input)>
            {
                ("Add", "123"),
                ("Insert", "abc"),
                ("Append", "Hello"),
                ("Format", "{0}"),
                ("Add", "<System.String>"),
                ("Insert", "<System.Collections.Generic.List`1[System.String]>"),
                ("Append", "<System.Text.StringBuilder>"),
                ("Format", "<System.String>")
            };

            foreach (var (methodName, input) in testInputs)
            {
                var isSafe = detector.IsSafe(input, methodName);
                Console.WriteLine($"Method: {methodName}, Input: {input}, Safe: {isSafe}");
            }

            Console.WriteLine("Injection detection demo complete.");
        }
    }
}