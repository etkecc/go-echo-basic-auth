# echo basic auth

Basic Auth middleware with constant time equality checks and optional IP whitelisting for Echo framework.
CIDRs are supported for IP whitelisting as well

## Usage

```go
auth := &echobasicauth.Auth{Login: "test", Password: "test", IPs: []string{"127.0.0.1", "10.0.0.0/24"}}
e.Use(echobasicauth.NewMiddleware(auth))
// or you can use echobasicauth.NewValidator(auth) if you want to define the middleware yourself
```

IP rules match the transport peer, so `X-Forwarded-For` and `X-Real-IP` cannot spoof an allowlisted
client. Proxy trust is opt-in:

```go
e.IPExtractor = echo.ExtractIPFromXFFHeader()
```

Without it, proxied clients are checked against the proxy address. `Auth.IPs` changes apply on the next
request. Invalid entries never open the whitelist: an all-invalid list denies everybody, and `Validate`
reports the typos, so they can fail the boot instead of the check:

```go
if err := auth.Validate(); err != nil {
    return err
}
```

Failed attempts are logged at WARN with the anonymized client address; Echo's default level is ERROR, so
raise it to see them: `e.Logger.SetLevel(log.WARN)`.

### IP validation without credentials

```go
auth := &echobasicauth.Auth{IPs: []string{"127.0.0.1", "10.0.0.0/24"}}
if auth.AllowedIP(echobasicauth.ClientIP(c)) {
    // IP is allowed
}
```

Use `ClientIP` instead of `c.RealIP()`: it ignores client headers unless `e.IPExtractor` is set, so the
check cannot be bypassed with a crafted request.
