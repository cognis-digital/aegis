import time
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import socket
import ssl
import asyncio
from asyncio import StreamReader, StreamWriter
from collections import deque

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SessionMonitor")

class SessionMonitor:
    def __init__(self, max_sessions: int = 100, session_timeout: int = 300):
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_lock = threading.Lock()
        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_sessions)
        self._monitor_thread.start()

    def _monitor_sessions(self):
        while self._running:
            with self.session_lock:
                now = datetime.now()
                sessions_to_remove = [sid for sid, session in self.active_sessions.items() if (now - session['last_active']) > timedelta(seconds=self.session_timeout)]
                for sid in sessions_to_remove:
                    del self.active_sessions[sid]
                    logger.info(f"Session {sid} expired and removed.")
            time.sleep(10)

    def start_session(self, session_id: str, user: str, ip: str, protocol: str):
        with self.session_lock:
            if len(self.active_sessions) >= self.max_sessions:
                oldest = min(self.active_sessions.items(), key=lambda x: x[1]['start_time'])[0]
                del self.active_sessions[oldest]
                logger.warning(f"Max sessions reached. Removed oldest session {oldest}.")

            session = {
                'session_id': session_id,
                'user': user,
                'ip': ip,
                'protocol': protocol,
                'start_time': datetime.now(),
                'last_active': datetime.now(),
                'credentials': [],
                'injections': [],
                'reach': []
            }
            self.active_sessions[session_id] = session
            logger.info(f"Started session {session_id} for user {user} from IP {ip} using {protocol}.")

    def end_session(self, session_id: str):
        with self.session_lock:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                logger.info(f"Ended session {session_id}.")

    def log_credentials(self, session_id: str, credentials: Dict[str, Any]):
        with self.session_lock:
            if session_id in self.active_sessions:
                self.active_sessions[session_id]['credentials'].append(credentials)
                logger.debug(f"Logged credentials for session {session_id}: {credentials}")

    def log_injection(self, session_id: str, injection: Dict[str, Any]):
        with self.session_lock:
            if session_id in self.active_sessions:
                self.active_sessions[session_id]['injections'].append(injection)
                logger.debug(f"Logged injection for session {session_id}: {injection}")

    def log_reach(self, session_id: str, reach: Dict[str, Any]):
        with self.session_lock:
            if session_id in self.active_sessions:
                self.active_sessions[session_id]['reach'].append(reach)
                logger.debug(f"Logged reach for session {session_id}: {reach}")

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        with self.session_lock:
            return [session for session in self.active_sessions.values()]

    def stop(self):
        self._running = False
        self._monitor_thread.join()


class SessionMonitorServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 9999, monitor: Optional[SessionMonitor] = None):
        self.host = host
        self.port = port
        self.monitor = monitor or SessionMonitor()
        self.server = None
        self.loop = asyncio.new_event_loop()

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        try:
            data = await reader.read(1024)
            message = data.decode().strip()
            logger.debug(f"Received message: {message}")
            parts = message.split()
            if not parts:
                return

            command = parts[0]
            args = parts[1:]

            if command == "START":
                session_id = args[0]
                user = args[1]
                ip = args[2]
                protocol = args[3]
                self.monitor.start_session(session_id, user, ip, protocol)
                writer.write(f"SESSION STARTED {session_id}\n".encode())
                await writer.drain()
            elif command == "END":
                session_id = args[0]
                self.monitor.end_session(session_id)
                writer.write(f"SESSION ENDED {session_id}\n".encode())
                await writer.drain()
            elif command == "LOG_CREDENTIALS":
                session_id = args[0]
                credentials = dict(arg.split('=') for arg in args[1:])
                self.monitor.log_credentials(session_id, credentials)
                writer.write(f"CREDS LOGGED {session_id}\n".encode())
                await writer.drain()
            elif command == "LOG_INJECTION":
                session_id = args[0]
                injection = dict(arg.split('=') for arg in args[1:])
                self.monitor.log_injection(session_id, injection)
                writer.write(f"INJ LOGGED {session_id}\n".encode())
                await writer.drain()
            elif command == "LOG_REACH":
                session_id = args[0]
                reach = dict(arg.split('=') for arg in args[1:])
                self.monitor.log_reach(session_id, reach)
                writer.write(f"REACH LOGGED {session_id}\n".encode())
                await writer.drain()
            elif command == "LIST":
                sessions = self.monitor.get_active_sessions()
                response = "\n".join([f"{s['session_id']} | {s['user']} | {s['ip']} | {s['protocol']}" for s in sessions])
                writer.write(f"ACTIVE SESSIONS:\n{response}\n".encode())
                await writer.drain()
            else:
                writer.write(f"UNKNOWN COMMAND: {command}\n".encode())
                await writer.drain()
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port, loop=self.loop)
        logger.info(f"Server started on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    def run(self):
        try:
            self.loop.run_until_complete(self.start())
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
            self.monitor.stop()
            self.loop.stop()


if __name__ == "__main__":
    monitor = SessionMonitor(max_sessions=50, session_timeout=600)
    server = SessionMonitorServer(host="localhost", port=9999, monitor=monitor)
    server.run()