using System;
using System.Collections.Generic;
using System.Linq;

namespace polyglot.csharp
{
    public class SessionMonitor
    {
        private readonly Dictionary<string, Session> _sessions = new Dictionary<string, Session>();
        private readonly List<AccessEvent> _accessEvents = new List<AccessEvent>();

        public void StartMonitoring()
        {
            Console.WriteLine("Session Monitor started.");
            SimulateSessionCreation();
            SimulateAccessEvents();
            AnalyzeSessions();
        }

        private void SimulateSessionCreation()
        {
            var session1 = new Session
            {
                Id = "S12345",
                UserId = "U001",
                StartTime = DateTime.Now,
                LastActivity = DateTime.Now,
                IsSecure = false,
                IsEncrypted = true,
                IsAuthenticated = true,
                IsAuthorized = true
            };
            _sessions[session1.Id] = session1;

            var session2 = new Session
            {
                Id = "S67890",
                UserId = "U002",
                StartTime = DateTime.Now.AddMinutes(-5),
                LastActivity = DateTime.Now.AddMinutes(-3),
                IsSecure = true,
                IsEncrypted = false,
                IsAuthenticated = true,
                IsAuthorized = false
            };
            _sessions[session2.Id] = session2;

            Console.WriteLine("Sessions created.");
        }

        private void SimulateAccessEvents()
        {
            var event1 = new AccessEvent
            {
                SessionId = "S12345",
                EventType = "SQL Injection",
                Timestamp = DateTime.Now.AddSeconds(-10),
                Details = "User input not sanitized."
            };
            _accessEvents.Add(event1);

            var event2 = new AccessEvent
            {
                SessionId = "S67890",
                EventType = "Data Exfiltration",
                Timestamp = DateTime.Now.AddSeconds(-5),
                Details = "Unrestricted access to sensitive data."
            };
            _accessEvents.Add(event2);

            Console.WriteLine("Access events simulated.");
        }

        private void AnalyzeSessions()
        {
            var lethalSessions = _sessions.Values
                .Where(s => !s.IsSecure || !s.IsEncrypted || s.IsAuthorized)
                .ToList();

            if (lethalSessions.Count > 0)
            {
                Console.WriteLine("Lethal sessions detected:");
                foreach (var session in lethalSessions)
                {
                    Console.WriteLine($"Session ID: {session.Id}, User: {session.UserId}");
                }

                var riskyEvents = _accessEvents
                    .Where(e => e.EventType == "SQL Injection" || e.EventType == "Data Exfiltration")
                    .ToList();

                if (riskyEvents.Count > 0)
                {
                    Console.WriteLine("Risky access events detected:");
                    foreach (var eventItem in riskyEvents)
                    {
                        Console.WriteLine($"Session ID: {eventItem.SessionId}, Event: {eventItem.EventType}");
                    }
                }
            }
            else
            {
                Console.WriteLine("No lethal sessions or risky events detected.");
            }
        }
    }

    public class Session
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime LastActivity { get; set; }
        public bool IsSecure { get; set; }
        public bool IsEncrypted { get; set; }
        public bool IsAuthenticated { get; set; }
        public bool IsAuthorized { get; set; }
    }

    public class AccessEvent
    {
        public string SessionId { get; set; }
        public string EventType { get; set; }
        public DateTime Timestamp { get; set; }
        public string Details { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var monitor = new SessionMonitor();
            monitor.StartMonitoring();
        }
    }
}