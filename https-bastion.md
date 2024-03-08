# HTTPS Bastion

This document specifies an HTTPS bastion, a service that acts as a reverse proxy
accepting connections from both clients and backends and routing requests from
the former to the latter.

Bastions allow backends to run in an environment without a publicly reachable
address, while still being reachable synchronously over a public HTTP endpoint.

The design requires no changes to HTTPS clients, and can be implemented as an
abstraction or even a separate service on the backend side with no changes to
most HTTP servers.

Backends are authenticated by their Ed25519 key, and the hash of that public key
becomes the first segment of the path of client requests. To prevent abuse, it
is RECOMMENDED that bastions apply an allowlisting or registration policy to the
backends they will serve.

Like regular HTTPS reverse proxies, the bastion is in the position of blocking,
observing, or manipulating the backend’s traffic. Bastions SHOULD only be used
for self-authenticating protocols, that don't rely exclusively on TLS for
authentication or confidentiality. Alternatively, backends MAY use bastions they
trust as part of their broad hosting infrastructure.

Bastions were designed to enable synchronous [transparency log witnesses][]
which prefer not to accept connections directly from the Internet.

## API

At a high level, backends connect to the bastion authenticating with their
Ed25519 key and start serving HTTP/2 on that connection. The bastion then
proxies to that connection all requests that include the backend's public key
hash in the URL path.

### Backend to bastion connection

A backend connects to the bastion’s backend endpoint with TLS 1.3, specifying
the ALPN protocol `bastion/0`. Other TLS versions MUST be rejected, as only TLS
1.3 hides client certificates from network observers. The backend MUST present as
its client certificate a self-signed Ed25519 certificate containing the backend
public key. The backend verifies the bastion’s TLS certificate chain like usual.
The bastion checks the backend public key against an allow list.

After opening the connection, the backend starts serving HTTP/2 traffic on it as
if it was a client-initiated connection. HTTP/2’s multiplexing allows serving
multiple parallel requests on a single connection efficiently. None of the
backend's HTTP APIs are modified, except for observing the `X-Forwarded-For`
header.

Appendix A presents an example Go adapter that turns a regular HTTP server into
a bastion backend.

### Client to bastion requests

The bastion accepts HTTP requests at

```
https://<bastion host>/<key hash>/<path>
```

where "key hash" MUST be a hex-encoded SHA-256 hash of a 32-byte Ed25519
public key.

If the backend key doesn’t correspond to any open backend connection, the
bastion MUST serve a 502 Bad Gateway response.

Otherwise, the bastion MUST remove _all_ `X-Forwarded-For` headers from the
request, add a single `X-Forwarded-For` header with the IP address of the
client, and proxy the request as `/<path>` over the backend connection. Note
that the `/<key hash>` portion of the path is trimmed.

The bastion MUST ignore all caching headers is both request and response.

## Appendix A — Example Go adapter

```go
func connectAndServe(host string, handler http.Handler, key ed25519.PrivateKey) {
	log.Printf("Connecting to bastion...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{
		Config: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{selfSignedCertificate(key)},
				PrivateKey:  key,
			}},
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	}).DialContext(ctx, "tcp", host)
	if err != nil {
		log.Printf("Failed to connect to bastion: %v", err)
		return
	}

	log.Printf("Connected to bastion. Serving connection...")
	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

func selfSignedCertificate(key ed25519.PrivateKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Bastion backend"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}
	return cert
}
```

## Appendix B — Security analysis of reusing a witness key

Transparency log witnesses MAY choose to reuse the witness key as their bastion
backend key.

If domain separation between the TLS handshake signatures, the X.509 certificate
self-signature, and the witness protocol signatures can’t be ensured, there’s a
risk of cross-protocol attacks.

   * TLS 1.3 handshake signatures for client certificates are always applied on
messages starting with 64 ASCII spaces followed by the string `TLS 1.3, client
CertificateVerify` (see RFC 8446, Section 4.4.3).

   * X.509 signatures are performed over the `TBSCertificate` ASN.1 STRUCTURE
which encoded with DER always starts with 0x30 (`0` in ASCII).

   * The witness protocol produces [cosignatures][], which format signed
messages with the prefix `cosignature/v1`.

The signed messages have no common prefix, guaranteeing domain separation.
