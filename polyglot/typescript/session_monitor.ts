// polyglot/typescript/session_monitor.ts

import { EventEmitter } from 'events';

interface Session {
  id: string;
  userId: string;
  startTime: Date;
  lastActivity: Date;
  status: 'active' | 'idle' | 'terminated';
  credentials: {
    token?: string;
    apiKey?: string;
    username?: string;
    password?: string;
  };
  injectionPoints: {
    [key: string]: any;
  };
  reach: {
    endpoints: string[];
    permissions: string[];
  };
}

interface SessionMonitorEvent {
  type: 'session_started' | 'session_ended' | 'session_injected' | 'session_reached';
  session: Session;
}

class SessionMonitor extends EventEmitter {
  private sessions: Map<string, Session> = new Map();

  constructor() {
    super();
  }

  startSession(sessionId: string, userId: string): void {
    const session: Session = {
      id: sessionId,
      userId,
      startTime: new Date(),
      lastActivity: new Date(),
      status: 'active',
      credentials: {},
      injectionPoints: {},
      reach: {
        endpoints: [],
        permissions: []
      }
    };

    this.sessions.set(sessionId, session);
    this.emit('session_started', session);
  }

  endSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.status = 'terminated';
    session.lastActivity = new Date();
    this.sessions.delete(sessionId);
    this.emit('session_ended', session);
  }

  injectIntoSession(sessionId: string, injectionData: { [key: string]: any }): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.injectionPoints = { ...session.injectionPoints, ...injectionData };
    session.lastActivity = new Date();
    this.emit('session_injected', session);
  }

  grantReach(sessionId: string, endpoints: string[], permissions: string[]): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.reach.endpoints = [...session.reach.endpoints, ...endpoints];
    session.reach.permissions = [...session.reach.permissions, ...permissions];
    session.lastActivity = new Date();
    this.emit('session_reached', session);
  }

  addCredentials(sessionId: string, credentials: { [key: string]: any }): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.credentials = { ...session.credentials, ...credentials };
    session.lastActivity = new Date();
    this.emit('session_credentials_updated', session);
  }

  getSession(sessionId: string): Session | undefined {
    return this.sessions.get(sessionId);
  }

  listSessions(): Session[] {
    return Array.from(this.sessions.values());
  }
}

// Demo
const monitor = new SessionMonitor();

monitor.on('session_started', (session) => {
  console.log(`Session started: ${session.id} for user ${session.userId}`);
});

monitor.on('session_ended', (session) => {
  console.log(`Session ended: ${session.id}`);
});

monitor.on('session_injected', (session) => {
  console.log(`Injection detected in session ${session.id}`);
});

monitor.on('session_reached', (session) => {
  console.log(`Session ${session.id} reached endpoints: ${session.reach.endpoints.join(', ')}`);
});

// Simulate session
monitor.startSession('sess_123', 'user_456');
monitor.addCredentials('sess_123', { token: 'abc123', apiKey: 'xyz789' });
monitor.injectIntoSession('sess_123', { payload: 'malicious_data' });
monitor.grantReach('sess_123', ['/api/data', '/admin/users'], ['read', 'write']);

console.log('Current sessions:', monitor.listSessions());