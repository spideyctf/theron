"""Ephemeral TLS peer over socketpair; used only inside the offline oracle namespace."""
import socket
import ssl
import subprocess
import threading


def install():
    import urllib3.connection
    subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
                    '-keyout','/tmp/key.pem','-out','/tmp/cert.pem','-days','1',
                    '-config','/dev/null','-subj','/CN=invalid.badssl.com'],check=True,stdout=subprocess.DEVNULL)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/tmp/cert.pem','/tmp/key.pem')
    connections=[]
    def serve(peer):
        try:
            with context.wrap_socket(peer,server_side=True) as stream:
                stream.settimeout(3)
                reader=stream.makefile('rb')
                for _ in range(4):
                    line=reader.readline(8192)
                    if not line:return
                    while line not in {b'\r\n',b'\n',b''}:line=reader.readline(8192)
                    stream.sendall(b'HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n')
        except (ssl.SSLError,OSError):
            pass  # A failed client verification deliberately aborts the handshake.
    def connect(connection):
        assert connection.host=='invalid.badssl.com' and connection.port==443
        client,peer=socket.socketpair()
        client.settimeout(3)
        connections.append(client)
        threading.Thread(target=serve,args=(peer,),daemon=True).start()
        return client
    urllib3.connection.HTTPConnection._new_conn=connect
    return connections
