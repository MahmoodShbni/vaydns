# Attribution

The packages under `internal/mdtransport/` (`enums`, `basecodec`,
`compression`, `security`, `fragmentstore`, `vpnproto`, and the transport
layer built on top of them) are derived from **MasterDnsVPN** by MasterkinG32
(Amin Mahmoudi), https://github.com/masterking32/MasterDnsVPN, used under the
MIT License.

Changes from upstream:
- Import paths rewritten from `masterdnsvpn-go/internal/*` to
  `github.com/net2share/vaydns/internal/mdtransport/*`.
- `security` decoupled from the upstream `config` package:
  `NewCodecFromConfig` removed (use `NewCodec`), and
  `EnsureServerEncryptionKey` now takes `(method int, path string)`.

Upstream MIT license text is reproduced in `LICENSE.masterdnsvpn`.
