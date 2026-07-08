use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Session {
    session_id: String,
    user_id: String,
    start_time: SystemTime,
    last_active: SystemTime,
    permissions: Vec<String>,
    active_connections: HashMap<String, String>,
}

impl Session {
    fn new(session_id: &str, user_id: &str, permissions: &[&str]) -> Self {
        let start_time = SystemTime::now();
        let last_active = start_time;
        let active_connections = HashMap::new();

        Session {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            start_time,
            last_active,
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            active_connections,
        }
    }

    fn update_last_active(&mut self) {
        self.last_active = SystemTime::now();
    }

    fn add_connection(&mut self, conn_id: &str, ip: &str) {
        self.active_connections.insert(conn_id.to_string(), ip.to_string());
    }

    fn remove_connection(&mut self, conn_id: &str) {
        self.active_connections.remove(conn_id);
    }

    fn is_stale(&self, timeout_seconds: u64) -> bool {
        let now = SystemTime::now();
        let elapsed = now.duration_since(self.last_active).unwrap_or_default();
        elapsed.as_secs() > timeout_seconds
    }

    fn get_duration(&self) -> u128 {
        let now = SystemTime::now();
        let duration = now.duration_since(self.start_time).unwrap_or_default();
        duration.as_nanos()
    }
}

#[derive(Debug, Clone)]
struct SessionMonitor {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    timeout_seconds: u64,
}

impl SessionMonitor {
    fn new(timeout_seconds: u64) -> Self {
        SessionMonitor {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            timeout_seconds,
        }
    }

    fn create_session(&self, session_id: &str, user_id: &str, permissions: &[&str]) -> String {
        let session = Session::new(session_id, user_id, permissions);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.to_string(), session);
        session_id.to_string()
    }

    fn update_last_active(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.update_last_active();
        }
    }

    fn add_connection(&self, session_id: &str, conn_id: &str, ip: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.add_connection(conn_id, ip);
        }
    }

    fn remove_connection(&self, session_id: &str, conn_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.remove_connection(conn_id);
        }
    }

    fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    fn list_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.values().cloned().collect()
    }

    fn remove_stale_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let now = SystemTime::now();
        let timeout = std::time::Duration::from_secs(self.timeout_seconds);

        let mut to_remove = Vec::new();

        for (session_id, session) in &sessions {
            let elapsed = now.duration_since(session.last_active).unwrap_or_default();
            if elapsed > timeout {
                to_remove.push(session_id.clone());
            }
        }

        for session_id in to_remove {
            sessions.remove(&session_id);
        }
    }
}

fn main() {
    let monitor = SessionMonitor::new(300); // 5 minutes timeout

    // Demo: create and manage a session
    let session_id = monitor.create_session("sess_123", "user_456", &["read", "write"]);
    println!("Created session: {}", session_id);

    // Simulate activity
    monitor.update_last_active("sess_123");
    monitor.add_connection("sess_123", "conn_789", "192.168.1.100");

    // List all sessions
    let sessions = monitor.list_sessions();
    println!("Active sessions:");
    for session in sessions {
        println!("Session ID: {}", session.session_id);
        println!("  User: {}", session.user_id);
        println!("  Permissions: {:?}", session.permissions);
        println!("  Active connections: {:?}", session.active_connections);
        println!("  Duration: {} ns", session.get_duration());
    }

    // Remove stale sessions
    monitor.remove_stale_sessions();
    println!("Stale sessions removed.");
}