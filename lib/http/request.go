package libhttp

import (
	"bufio"
	//"bytes"
	//"context"
	//"crypto/tls"
	//"encoding/base64"
	"errors"
	"fmt"
	"io"
	//"io/ioutil"
	//"mime"
	//"mime/multipart"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	//"strconv"
	"strings"
	"sync"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"
)

var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")


// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

func isReplayable(r *http.Request) bool {
	if r.Body == nil {
		switch valueOrDefault(r.Method, "GET") {
		case "GET", "HEAD", "OPTIONS", "TRACE":
			return true
		}
	}
	return false
}

func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// outgoingLength reports the Content-Length of this outgoing (Client) request.
// It maps 0 into -1 (unknown) when the Body is non-nil.
func outgoingLength(r *http.Request) int64 {
	if r.Body == nil || r.Body == http.NoBody {
		return 0
	}
	if r.ContentLength != 0 {
		return r.ContentLength
	}
	return -1
}


func protoAtLeastOutgoing(r *http.Request, major, minor int) bool {
	if r.ProtoMajor == 0 && r.ProtoMinor == 0 && major == 1 && minor <= 1 {
		return true
	}
	return r.ProtoAtLeast(major, minor)
}

func idnaASCII(v string) (string, error) {
	if isASCII(v) {
		return v, nil
	}
	// The idna package doesn't do everything from
	// https://tools.ietf.org/html/rfc5895 so we do it here.
	// TODO(bradfitz): should the idna package do this instead?
	v = strings.ToLower(v)
	v = width.Fold.String(v)
	v = norm.NFC.String(v)
	return idna.ToASCII(v)
}

func cleanHost(in string) string {
	if i := strings.IndexAny(in, " /"); i != -1 {
		in = in[:i]
	}
	host, port, err := net.SplitHostPort(in)
	if err != nil { // input was just a host
		a, err := idnaASCII(in)
		if err != nil {
			return in // garbage in, garbage out
		}
		return a
	}
	a, err := idnaASCII(host)
	if err != nil {
		return in // garbage in, garbage out
	}
	return net.JoinHostPort(a, port)
}


// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

const defaultUserAgent = "Go-http-client/1.1"

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	"Host":              true, // not in Header map anyway
	"User-Agent":        true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// extraHeaders may be nil
// waitForContinue may be nil
func write(req *http.Request, w io.Writer, usingProxy bool, extraHeaders http.Header, waitForContinue func() bool) (err error) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace != nil && trace.WroteRequest != nil {
		defer func() {
			trace.WroteRequest(httptrace.WroteRequestInfo{
				Err: err,
			})
		}()
	}

	// Find the target host. Prefer the Host: header, but if that
	// is not given, use the host from the request URL.
	//
	// Clean the host, in case it arrives with unexpected stuff in it.
	host := cleanHost(req.Host)
	if host == "" {
		if req.URL == nil {
			return errMissingHost
		}
		host = cleanHost(req.URL.Host)
	}

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	host = removeZone(host)

	ruri := req.URL.RequestURI()
	if usingProxy && req.URL.Scheme != "" && req.URL.Opaque == "" {
		ruri = req.URL.Scheme + "://" + host + ruri
	} else if req.Method == "CONNECT" && req.URL.Path == "" {
		// CONNECT requests normally give just the host and port, not a full URL.
		ruri = host
	}
	// TODO(bradfitz): escape at least newlines in ruri?

	// Wrap the writer in a bufio Writer if it's not already buffered.
	// Don't always call NewWriter, as that forces a bytes.Buffer
	// and other small bufio Writers to have a minimum 4k buffer
	// size.
	var bw *bufio.Writer
	if _, ok := w.(io.ByteWriter); !ok {
		bw = bufio.NewWriter(w)
		w = bw
	}

	_, err = fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", valueOrDefault(req.Method, "GET"), ruri)
	if err != nil {
		return err
	}

	// Header lines
	_, err = fmt.Fprintf(w, "Host: %s\r\n", host)
	if err != nil {
		return err
	}

	// Use the defaultUserAgent unless the Header contains one, which
	// may be blank to not send the header.
	userAgent := defaultUserAgent
	if _, ok := req.Header["User-Agent"]; ok {
		userAgent = req.Header.Get("User-Agent")
	}
	if userAgent != "" {
		_, err = fmt.Fprintf(w, "User-Agent: %s\r\n", userAgent)
		if err != nil {
			return err
		}
	}

	// Process Body,ContentLength,Close,Trailer
	tw, err := newTransferWriter(req)
	if err != nil {
		return err
	}
	err = tw.WriteHeader(w)
	if err != nil {
		return err
	}

	err = req.Header.WriteSubset(w, reqWriteExcludeHeader)
	if err != nil {
		return err
	}

	if extraHeaders != nil {
		err = extraHeaders.Write(w)
		if err != nil {
			return err
		}
	}

	_, err = io.WriteString(w, "\r\n")
	if err != nil {
		return err
	}

	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}

	// Flush and wait for 100-continue if expected.
	if waitForContinue != nil {
		if bw, ok := w.(*bufio.Writer); ok {
			err = bw.Flush()
			if err != nil {
				return err
			}
		}
		if trace != nil && trace.Wait100Continue != nil {
			trace.Wait100Continue()
		}
		if !waitForContinue() {
			closeBody(req)
			return nil
		}
	}

	if bw, ok := w.(*bufio.Writer); ok && tw.FlushHeaders {
		if err := bw.Flush(); err != nil {
			return err
		}
	}

	// Write body and trailer
	err = tw.WriteBody(w)
	if err != nil {
		return err
	}

	if bw != nil {
		return bw.Flush()
	}
	return nil
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}

// Constants for readRequest's deleteHostHeader parameter.
const (
	deleteHostHeader = true
	keepHostHeader   = false
)

func readRequest(b *bufio.Reader, deleteHostHeader bool) (req *http.Request, err error) {
	tp := newTextprotoReader(b)
	req = new(http.Request)

	// First line: GET /index.html HTTP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	var ok bool
	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)
	if !ok {
		return nil, &badStringError{"malformed HTTP request", s}
	}
	rawurl := req.RequestURI
	if req.ProtoMajor, req.ProtoMinor, ok = http.ParseHTTPVersion(req.Proto); !ok {
		return nil, &badStringError{"malformed HTTP version", req.Proto}
	}

	// CONNECT requests are used two different ways, and neither uses a full URL:
	// The standard use is to tunnel HTTPS through an HTTP proxy.
	// It looks like "CONNECT www.google.com:443 HTTP/1.1", and the parameter is
	// just the authority section of a URL. This information should go in req.URL.Host.
	//
	// The net/rpc package also uses CONNECT, but there the parameter is a path
	// that starts with a slash. It can be parsed with the regular URL parser,
	// and the path will end up in req.URL.Path, where it needs to be in order for
	// RPC to work.
	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
	if justAuthority {
		rawurl = "http://" + rawurl
	}

	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return nil, err
	}

	if justAuthority {
		// Strip the bogus "http://" back off.
		req.URL.Scheme = ""
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = http.Header(mimeHeader)

	// RFC 2616: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same. In the second case, any Host line is ignored.
	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = get(req.Header, "Host")
	}
	if deleteHostHeader {
		delete(req.Header, "Host")
	}

	fixPragmaCacheControl(req.Header)

	req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header, false)

	err = readTransfer(req, b)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func fixPragmaCacheControl(header http.Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}


func clone(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// get is like Get, but key must already be in CanonicalHeaderKey form.
func get(h http.Header, key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}
		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}
		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}
		if strings.EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}
	return false
}

func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}

func wantsHttp10KeepAlive(r *http.Request) bool {
	if r.ProtoMajor != 1 || r.ProtoMinor != 0 {
		return false
	}
	return hasToken(get(r.Header, "Connection"), "keep-alive")
}


func wantsClose(r *http.Request) bool {
	return hasToken(get(r.Header, "Connection"), "close")
}

func expectsContinue(r *http.Request) bool {
	return hasToken(get(r.Header, "Expect"), "100-continue")
}


// requestMethodUsuallyLacksBody reports whether the given request
// method is one that typically does not involve a request body.
// This is used by the Transport (via
// transferWriter.shouldSendChunkedRequestBody) to determine whether
// we try to test-read a byte from a non-nil Request.Body when
// Request.outgoingLength() returns -1. See the comments in
// shouldSendChunkedRequestBody.
func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}
