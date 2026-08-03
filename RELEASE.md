# Releasing

The hosted and downloadable releases are independent:

- Netlify runs `npm ci && npm run build:verified` and publishes `dist/` to
  <https://offline-wallet-generator.theqrl.org>.
- A signed `v*` tag builds `dist-offline/index.html`, checks that it is
  self-contained, and publishes the HTML plus its SHA-256 on GitHub Releases.

## Cut an offline release

1. Bump and commit the version: `npm version <version> --no-git-tag-version`.
2. Merge and confirm the Netlify deployment first.
3. Sign the deployed commit: `git tag -s v<version> -m "QRL Offline Wallet <version>"`.
4. Verify it locally: `git verify-tag v<version>`.
5. Push it: `git push origin v<version>`.

The release workflow rejects lightweight or unsigned tags and tags whose
version differs from `package.json`.

Verify a download with:

```bash
sha256sum -c qrl-offline-wallet-<version>.html.sha256
```

Rebuild it from the tagged commit with:

```bash
npm ci && npm run build:offline
sha256sum dist-offline/index.html
```
