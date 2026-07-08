using System;
using System.Collections.Generic;
using System.Linq;

namespace polyglot.csharp
{
    // Represents a user with associated permissions
    public class User
    {
        public string Username { get; set; }
        public List<string> Permissions { get; set; } = new List<string>();
    }

    // Represents an API endpoint with required permissions
    public class Endpoint
    {
        public string Name { get; set; }
        public List<string> RequiredPermissions { get; set; } = new List<string>();
    }

    // Represents a database table with access permissions
    public class DatabaseTable
    {
        public string TableName { get; set; }
        public List<string> AccessPermissions { get; set; } = new List<string>();
    }

    // Permission Mapper class to analyze user permissions against endpoints and databases
    public class PermissionMapper
    {
        private readonly List<User> _users;
        private readonly List<Endpoint> _endpoints;
        private readonly List<DatabaseTable> _databaseTables;

        public PermissionMapper(List<User> users, List<Endpoint> endpoints, List<DatabaseTable> databaseTables)
        {
            _users = users;
            _endpoints = endpoints;
            _databaseTables = databaseTables;
        }

        // Maps user permissions to endpoints and databases
        public void MapPermissions()
        {
            Console.WriteLine("=== Permission Mapping Report ===");

            // Map user permissions to endpoints
            foreach (var user in _users)
            {
                Console.WriteLine($"\nUser: {user.Username}");
                foreach (var endpoint in _endpoints)
                {
                    var hasAccess = user.Permissions.Intersect(endpoint.RequiredPermissions).Any();
                    Console.WriteLine($"  Endpoint: {endpoint.Name} - Access: {hasAccess}");
                }
            }

            // Map user permissions to database tables
            foreach (var user in _users)
            {
                Console.WriteLine($"\nUser: {user.Username}");
                foreach (var table in _databaseTables)
                {
                    var hasAccess = user.Permissions.Intersect(table.AccessPermissions).Any();
                    Console.WriteLine($"  Database Table: {table.TableName} - Access: {hasAccess}");
                }
            }

            Console.WriteLine("=== End of Report ===");
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Sample data for demonstration
            var users = new List<User>
            {
                new User { Username = "alice", Permissions = new List<string> { "read", "write" } },
                new User { Username = "bob", Permissions = new List<string> { "read" } }
            };

            var endpoints = new List<Endpoint>
            {
                new Endpoint { Name = "/api/data", RequiredPermissions = new List<string> { "read", "write" } },
                new Endpoint { Name = "/api/admin", RequiredPermissions = new List<string> { "admin" } }
            };

            var databaseTables = new List<DatabaseTable>
            {
                new DatabaseTable { TableName = "users", AccessPermissions = new List<string> { "read", "delete" } },
                new DatabaseTable { TableName = "logs", AccessPermissions = new List<string> { "read" } }
            };

            var mapper = new PermissionMapper(users, endpoints, databaseTables);
            mapper.MapPermissions();
        }
    }
}