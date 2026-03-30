# cookie2ghsecret

A standalone Windows executable that extracts a named cookie from a locally
installed Google Chrome browser and uploads it as a GitHub Actions repository
secret.

## Features

- Reads cookies directly from Chrome's SQLite database (no need to start a
  browser or use debugging protocols)
- Handles Chrome v80+ AES-256-GCM cookie encryption via Windows DPAPI
- Also supports older DPAPI-only encrypted cookies
- Works with Chrome, Chrome Canary, and Chromium
- No runtime dependencies — single `.exe`, nothing to install
- Configurable via a simple JSON file

## Usage

1. Copy `config.json.example` to `config.json` and fill in your values:

```json
{
  "website":            "example.com",
  "cookie_name":        "session_id",
  "github_repo":        "owner/repository",
  "github_token":       "ghp_your_token_here",
  "github_secret_name": "MY_COOKIE_SECRET"
}
```

| Field | Description |
|---|---|
| `website` | Domain (or part of it) to match cookies against, e.g. `example.com` |
| `cookie_name` | Name of the cookie to extract |
| `github_repo` | Repository in `owner/repo` format |
| `github_token` | GitHub personal access token with `repo` (secrets write) scope |
| `github_secret_name` | Name of the Actions secret to create or update |

2. Run the executable (use an optional argument to specify a different config path):

```cmd
cookie2ghsecret.exe
cookie2ghsecret.exe path\to\my-config.json
```

## Building

Requires Go 1.25+. Cross-compile from any OS:

```sh
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cookie2ghsecret.exe .
```

## Releases

Pushing a change to the `VERSION` file on the `main` branch automatically
triggers a GitHub Actions workflow that builds the Windows executable and
creates a new release with it as an attached artifact.

## How it works

1. Reads `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` to obtain the
   AES-256 key (encrypted with Windows DPAPI).
2. Copies the Cookies SQLite database to a temporary file (so Chrome does not
   need to be closed).
3. Queries the cookie by domain and name, then decrypts its value.
4. Fetches the repository's Actions public key from the GitHub API.
5. Encrypts the cookie value with the public key using the libsodium
   `crypto_box_seal` algorithm (X25519 + BLAKE2b nonce + XSalsa20-Poly1305).
6. Uploads the encrypted value via the GitHub Actions secrets API.
