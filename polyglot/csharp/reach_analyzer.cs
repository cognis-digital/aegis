using System;
using System.Collections.Generic;
using System.Linq;

namespace polyglot.csharp
{
    // Represents a system component with its name and access level
    public class Component
    {
        public string Name { get; set; }
        public int AccessLevel { get; set; } // 0 - Public, 1 - Protected, 2 - Private
    }

    // Represents a user with their credentials and permissions
    public class User
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public List<string> Permissions { get; set; } = new List<string>();
    }

    // Represents an injection point in the system
    public class InjectionPoint
    {
        public string Name { get; set; }
        public string Type { get; set; } // e.g., SQL, XSS, Command Injection
        public bool IsVulnerable { get; set; }
    }

    // Reach Analyzer class to identify potential reach in the system
    public class ReachAnalyzer
    {
        private List<Component> components = new List<Component>();
        private List<User> users = new List<User>();
        private List<InjectionPoint> injectionPoints = new List<InjectionPoint>();

        public void AddComponent(string name, int accessLevel)
        {
            components.Add(new Component { Name = name, AccessLevel = accessLevel });
        }

        public void AddUser(string username, string passwordHash, List<string> permissions)
        {
            users.Add(new User { Username = username, PasswordHash = passwordHash, Permissions = permissions });
        }

        public void AddInjectionPoint(string name, string type, bool isVulnerable)
        {
            injectionPoints.Add(new InjectionPoint { Name = name, Type = type, IsVulnerable = isVulnerable });
        }

        public void AnalyzeReach()
        {
            Console.WriteLine("=== Reach Analyzer Report ===");
            Console.WriteLine("Analyzing system components, users, and injection points...");

            // Check for high access components that are reachable by low-privilege users
            var highAccessComponents = components.Where(c => c.AccessLevel >= 2).ToList();
            var lowPrivilegeUsers = users.Where(u => u.Permissions.Count <= 2).ToList();

            Console.WriteLine("\nHigh Access Components (Private/Protected):");
            foreach (var comp in highAccessComponents)
            {
                Console.WriteLine($"- {comp.Name} (Access Level: {comp.AccessLevel})");
            }

            Console.WriteLine("\nLow Privilege Users:");
            foreach (var user in lowPrivilegeUsers)
            {
                Console.WriteLine($"- {user.Username} (Permissions: {string.Join(", ", user.Permissions)})");
            }

            // Check for vulnerable injection points that are accessible by users with low permissions
            var vulnerableInjectionPoints = injectionPoints.Where(ip => ip.IsVulnerable).ToList();
            var usersWithLowPermissions = users.Where(u => u.Permissions.Count <= 2).ToList();

            Console.WriteLine("\nVulnerable Injection Points:");
            foreach (var ip in vulnerableInjectionPoints)
            {
                Console.WriteLine($"- {ip.Name} ({ip.Type})");
            }

            Console.WriteLine("\nUsers with Low Permissions:");
            foreach (var user in usersWithLowPermissions)
            {
                Console.WriteLine($"- {user.Username}");
            }

            // Check if any low privilege user can access a high access component through a vulnerable injection point
            var potentialReach = from user in usersWithLowPermissions
                                from comp in highAccessComponents
                                from ip in vulnerableInjectionPoints
                                select new
                                {
                                    User = user.Username,
                                    Component = comp.Name,
                                    InjectionPoint = ip.Name
                                };

            Console.WriteLine("\nPotential Reach (User -> High Access Component via Vulnerable Injection Point):");
            foreach (var item in potentialReach)
            {
                Console.WriteLine($"- {item.User} can reach {item.Component} through {item.InjectionPoint}");
            }

            Console.WriteLine("=== End of Report ===");
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Initialize the Reach Analyzer
            var analyzer = new ReachAnalyzer();

            // Add components
            analyzer.AddComponent("Database", 2); // Private
            analyzer.AddComponent("API Gateway", 1); // Protected
            analyzer.AddComponent("User Interface", 0); // Public

            // Add users
            analyzer.AddUser("admin", "hash123", new List<string> { "read", "write" });
            analyzer.AddUser("guest", "hash456", new List<string> { "read" });
            analyzer.AddUser("developer", "hash789", new List<string> { "read", "write", "debug" });

            // Add injection points
            analyzer.AddInjectionPoint("SQL Injection in Login", "SQL", true);
            analyzer.AddInjectionPoint("XSS in UI", "XSS", false);
            analyzer.AddInjectionPoint("Command Injection in API", "Command", true);

            // Run the analysis
            analyzer.AnalyzeReach();
        }
    }
}