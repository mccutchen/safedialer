# safedialer

Package safedialer provides a [net.Dialer][dialer] `Control` function that
permits only TCP connections to port 80 and 443 on public IP addresses, so that
an application may safely connect to possibly-malicious URLs controlled by
external clients.

This code is _very_ lightly adapted from [Andrew Ayer][]'s excellent 2019 blog
post ["Preventing Server Side Request Forgery in Golang"][blog], which explains
the dangers of connecting to arbitrary URLs from your own application code.


## Example usage

```go
import (
    "fmt"
    "net"
    "net/http"

    "github.com/mccutchen/safedialer"
)

safeClient := &http.Client{
    Transport: &http.Transport{
        DialContext: (&net.Dialer{
            Control: safedialer.Control,
        }).DialContext,
    },
}

// Our safeClient will reject this request for a URL that resolves to a
// private IP address.
resp, err := safeClient.Get("http://www.10.0.0.1.nip.io")
if err != nil {
    fmt.Println("Prevented possibly malicious request")
}
```


## Authors

Written by [Andrew Ayer][].

GitHub repo and test suite added by [Will McCutchen][].


## Copying

All the content within this repository is dedicated to the public domain under
the [CC0 1.0 Universal (CC0 1.0) Public Domain Dedication][cc-zero].

[Andrew Ayer]: https://agwa.name
[blog]: https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang
[cc-zero]: https://creativecommons.org/publicdomain/zero/1.0/
[dialer]: https://golang.org/pkg/net/#Dialer
[Will McCutchen]: https://github.com/mccutchen
