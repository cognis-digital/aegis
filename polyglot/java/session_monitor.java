import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

public class session_monitor {
    private static final Logger logger = Logger.getLogger(session_monitor.class.getName());
    private static final int MAX_SESSIONS = 100;
    private static final int SESSION_TIMEOUT_MS = 30000;
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private static final Map<String, Session> activeSessions = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        logger.info("Starting AI Agent Permission & Access Auditor - Session Monitor");

        // Start session cleanup task
        scheduler.scheduleAtFixedRate(SessionMonitor::cleanupExpiredSessions, 10, 10, TimeUnit.SECONDS);

        // Simulate some sessions for demo
        simulateSessions();

        // Keep the main thread alive
        try {
            Thread.sleep(60000);
        } catch (InterruptedException e) {
            logger.severe("Main thread interrupted: " + e.getMessage());
        }

        scheduler.shutdown();
        logger.info("Session Monitor shutdown complete.");
    }

    private static void simulateSessions() {
        for (int i = 0; i < 10; i++) {
            String sessionId = UUID.randomUUID().toString();
            String userId = "user_" + i;
            String ipAddress = "192.168.1." + (i + 1);
            String userAgent = "Agent-" + i;

            Session session = new Session(sessionId, userId, ipAddress, userAgent, System.currentTimeMillis());
            activeSessions.put(sessionId, session);
            logger.info("Session created: " + session.toString());
        }
    }

    private static void cleanupExpiredSessions() {
        long currentTime = System.currentTimeMillis();
        List<String> expiredSessionIds = new ArrayList<>();

        for (Map.Entry<String, Session> entry : activeSessions.entrySet()) {
            Session session = entry.getValue();
            if (currentTime - session.getStartTime() > SESSION_TIMEOUT_MS) {
                expiredSessionIds.add(entry.getKey());
            }
        }

        for (String sessionId : expiredSessionIds) {
            activeSessions.remove(sessionId);
            logger.info("Session expired: " + sessionId);
        }
    }

    private static class Session {
        private final String id;
        private final String userId;
        private final String ipAddress;
        private final String userAgent;
        private final long startTime;

        public Session(String id, String userId, String ipAddress, String userAgent, long startTime) {
            this.id = id;
            this.userId = userId;
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.startTime = startTime;
        }

        @Override
        public String toString() {
            return "Session{" +
                   "id='" + id + '\'' +
                   ", userId='" + userId + '\'' +
                   ", ipAddress='" + ipAddress + '\'' +
                   ", userAgent='" + userAgent + '\'' +
                   ", startTime=" + new Date(startTime) +
                   '}';
        }
    }
}