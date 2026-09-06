# ace-datasource-vmalert

Compile-time VMAlert datasource module for [Ace](https://github.com/aceobservability/ace).

VMAlert is not a query `Client`. Ace does not `RegisterDatasource("vmalert")`.
Connection tests stay on Ace's `TestConnection` path, which injects
`ssrf.DatasourceClient` and runs the SSRF/CodeQL barrier. This module does not
import Ace `internal/` packages and does not construct an unpolicy'd client.

## Contract

| Surface | Value |
| --- | --- |
| Ace type key | `vmalert` (`Type`) |
| Factory | `New(url string, httpClient *http.Client)` |
| Query registry | none |

`httpClient` is required. Ace passes `ssrf.DatasourceClient` wrapped with stored
datasource credentials.

## Tests

```
go test ./...
```

Connection and API tests speak to an `httptest` fixture. No live VMAlert is
required.
