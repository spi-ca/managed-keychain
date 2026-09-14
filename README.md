# Managed Keychain

> **실험적 PKI 도구입니다.** 테스트 통과가 운영환경의 신뢰 체인·폐기 적용을
> 보증하지 않습니다. 운영 전 대상 TLS/MySQL, Kubernetes, 커널/Secure Boot 환경에서
> 검증하고 CA 상태를 백업하세요. 기본 개인키는 암호화하지 않으며, 이 도구는
> 노드 신뢰 저장소 등록이나 서비스 재시작을 자동 수행하지 않습니다.
>
> [MIT 라이선스](LICENSE)로 제공됩니다.

`managed-keychain`은 OpenSSL을 사용하는 선언형 ECC PKI 도구입니다. **정상 운영
흐름은 두 명령뿐입니다.** 정책 TOML에 원하는 Root/Intermediate와 leaf의 이름,
Subject, SAN, 유효기간 세대(generation), `active`/`revoked` 상태를 적고 계획을
확인한 뒤에만 적용합니다.

```sh
# 체크아웃 루트에서: ./config/keychain.toml을 찾는다.
uv run managed-keychain plan
uv run managed-keychain apply

# 설치된 wheel 또는 다른 디렉터리에서는 외부 정책을 반드시 명시한다.
managed-keychain --config /srv/pki/keychain.toml plan
managed-keychain --config /srv/pki/keychain.toml apply
```

`plan`은 읽기 전용입니다. 상태 디렉터리, 키, 인증서, CA DB, CRL을 만들거나
수정하지 않습니다. 현재 디렉터리에 `config/keychain.toml`이 없으면 숨은 기본값을
사용하지 않고 `--config`를 요구합니다. `apply`만 OpenSSL과 파일을 변경합니다.

## 정책

단 하나의 정식 예제/정책 위치는 프로젝트 루트의 `config/`입니다.
`config/keychain.toml`은 실제 서버 이름이나 SAN을 넣지 않은 안전한 예제이며, leaf
항목을 추가하기 전 `apply`는 CA hierarchy만 만듭니다. 배포용 정책은 이 파일을
복사해 안전한 외부 위치에 두고 `--config`로 지정하십시오. 패키지 `src/`에는
기본 TOML, OpenSSL 설정, 키, 인증서가 포함되지 않습니다.

```toml
[leaves.mysql-server]
profile = "tls-server"
domain = "tls"                # profile의 issuer_domain과 반드시 일치
desired = "active"             # active | revoked
generation = 2                  # 회전/갱신할 때 명시적으로 증가
revoked_generations = [1]        # active successor가 이전 immutable record를 revoke
common_name = "mysql.internal"
san = "DNS:mysql.internal,IP:192.0.2.10"

[leaves.api-server]
profile = "kubernetes-server"
domain = "kubernetes"
desired = "active"
generation = 1
common_name = "api.cluster.internal"
san = "DNS:api.cluster.internal,IP:192.0.2.20"

[leaves.module-signer]
profile = "code-signing"
domain = "code-signing"
desired = "active"
generation = 1
common_name = "spi-ca kernel code-sign"
```

`tls-server`와 `kubernetes-server`에는 SAN이 필수이고 client/code-signing 프로필에는
SAN을 넣을 수 없습니다. `domain`은 profile에 연결된 issuer domain과 반드시 같아야 하며
CLI에서 바꿀 수 없습니다.
## 암호 알고리즘 상속과 서명 규칙

기본값은 `secp384r1`(P-384)과 `sha384`입니다. `curve`는
`prime256v1`/`P256`, `secp384r1`/`P384`, `secp521r1`/`P521`를, `digest`는
`SHA256`, `SHA384`, `SHA512`를 대소문자와 관계없이 받습니다. 설정은 다음 순서로
상속합니다.

| 대상 | 설정 위치 | `curve`의 의미 | `digest`의 의미 |
| --- | --- | --- | --- |
| 공통 기본값 | `[pki]` | Root, 모든 Intermediate, 모든 leaf의 기본 key curve | 각 역할의 기본 signing digest |
| Root | `[pki.root]` | Root 공개키 | self-signed Root certificate 서명 |
| Intermediate domain | `[domains.<name>]` | 그 Intermediate 공개키 | 그 Intermediate가 leaf certificate와 CRL에 하는 서명 |
| leaf generation | `[leaves.<name>]` | leaf 공개키 | leaf CSR self-signature |

따라서 **certificate의 서명 digest는 subject leaf가 아니라 issuer의 policy**에서
옵니다. 예를 들어 P-521 leaf가 `SHA512`를 지정해 CSR을 만들더라도, `tls` domain이
`SHA256`이면 leaf certificate와 TLS CRL은 `ecdsa-with-SHA256`입니다. Intermediate
certificate는 항상 Root의 digest로 서명됩니다.

```toml
[pki]
curve = "P384"
digest = "SHA384"

[pki.root]                 # 선택: Root만 override
curve = "secp384r1"
digest = "SHA384"

[domains.tls]              # 기존 directory/CN 설정에 추가
curve = "P256"
digest = "SHA256"

[leaves.mysql-server]      # 기존 leaf 선언에 추가
curve = "P521"
digest = "SHA512"
```

새 CA 또는 새 leaf generation을 만들기 전에만 이 값을 변경하십시오. 생성된 Root와
Intermediate는 `crypto-policy.json`, leaf는 immutable `metadata.json`에 effective
curve/digest를 기록합니다. 기존 CA의 policy가 다르면 자동 rekey/reissue하지 않고
오류로 멈춥니다. 이전 값을 복구하거나 별도 CA hierarchy를 bootstrap해야 합니다.
기존 leaf의 crypto 변경도 generation을 올려야 합니다. 기본 policy의 유효기간은 Root
100년, Intermediate 10년, leaf 3년이고 child 유효기간은 항상 issuer보다 짧게 제한됩니다.

## 상태, 멱등성 및 회전

상대 상태 경로는 policy의 `pki.base_dir`을 기준으로 해석하며, 절대 경로를 지정하면
그 위치를 그대로 사용합니다. 기본 설정은 프로젝트의 `state/` 아래를 사용합니다.
leaf는 다음처럼 immutable record로 보존됩니다.

```text
state/<domain>/identities/<name>/generation-<N>/
  private/key.pem                  # 0600
  csr/request.csr
  issued/certificate.crt
  issued/certificate.chain.crt     # TLS: leaf + Intermediate
  metadata.json                    # subject, SAN, profile, domain, generation, curve, digest
```

CA private 디렉터리와 OpenSSL index/serial/CRL-number DB는 0700/0600으로 만들고
issuer별 잠금으로 `openssl ca` DB 변경을 직렬화합니다. 기존 파일은 덮어쓰지 않으며
symlink 경로도 거부합니다. 실패한 새 CA 디렉터리는 조사할 수 있도록 남기며, 호출자가
지정한 CA 디렉터리를 재귀 삭제하지 않습니다.

동일 policy의 두 번째 `plan`/`apply`는 변경이 없습니다. 갱신·회전은 자동 재발급이
아니라 `generation = 2`처럼 명시적으로 새 immutable record를 만드는 작업입니다.
기존 generation의 Subject, SAN, profile, domain은 `metadata.json`과 비교하며 바꿀 수
없습니다. 변경하려면 generation을 올리십시오. metadata가 없는 이전 도구 버전의 record도
안전하게 비교할 수 없으므로 generation을 올려 교체해야 합니다. 이전 generation은 보존됩니다.
active successor에서 `revoked_generations = [1]`처럼 이전 record를 명시적으로 revoke할 수
있습니다(값은 현재 generation보다 작고 중복될 수 없습니다). 이미 revoked인 세대를
`active`로 되돌릴 수 없고, 새 generation이 필요합니다. 존재하지 않는 generation을
`revoked`로 선언하거나 `revoked_generations`에 넣으면 apply는 no-op 대신 오류를 냅니다.

## 폐기와 CRL

기존 leaf의 `desired = "revoked"`를 적용하면 해당 Intermediate의 실제 OpenSSL
`db/index.txt` record를 revoke하고 `state/<domain>/ca/crl/issuer.crl`을 생성합니다.
이미 revoked인 identity는 다시 발급되지 않습니다. CRL 파일만 분실된 경우에는 현재
policy의 leaf 목록이 아니라 유지된 CA DB의 revoke history에서 다시 생성합니다. CRL은
유효기간은 `default_crl_days = 30`이며, 남은 기간이 `pki.crl_refresh_before_days`
(기본 7일)보다 짧을 때 `apply`가 갱신합니다. 예를 들어 매일 `plan`/`apply`를 실행하고
갱신된 CRL을 배포해야 합니다. 갱신 구간보다 일찍 한 번 실행하는 것만으로는 이후 만료를
방지하지 못합니다.

MySQL에서 CRL을 실제로 쓰려면 CA bundle과 CRL을 **서버가 읽을 수 있는 PEM 파일**로
배포하고 사용 중인 MySQL 버전의 `ssl_ca`, `ssl_crl` (또는 `ssl_crlpath`) 설정과
CRL reload/restart 동작을 검증해야 합니다. 이 도구는 파일만 export하며 MySQL 설정,
컨테이너 mount, reload를 변경하지 않습니다. 다음 검증은 CA/CRL 경로가 맞는지
확인하는 예입니다.

```sh
openssl verify -crl_check \
  -CAfile state/ca/certs/root-ca.crt \
  -untrusted state/tls/ca/certs/intermediate.crt \
  -CRLfile state/tls/ca/crl/issuer.crl \
  state/tls/identities/mysql-server/generation-1/issued/certificate.crt
```

폐기된 인증서에서는 검증이 의도적으로 실패합니다.

## 도메인별 export와 적용 한계

* TLS: `state/tls/node-ca-chain.crt`는 **TLS Intermediate + Root** 공개 trust bundle이고,
  각 TLS leaf의 `certificate.chain.crt`는 **leaf + Intermediate** serving chain입니다.
  Root를 서버 serving chain에 넣지 마십시오.
* Kubernetes: `state/kubernetes/node-ca-chain.crt`는 Kubernetes 전용 공개 bundle입니다.
  API server, kubelet, etcd, front-proxy의 역할, RBAC, secret mount/reload는 자동 구성하지
  않습니다. Kubernetes의 인증서/ConfigMap/host trust를 live write하지 않습니다.
* Kernel: code-signing leaf마다
  `state/kernel/<name>/generation-<N>/`에 Root, Intermediate, leaf 공개 export와
  `module-signing-key.pem`(leaf 개인키 + leaf 인증서)을 immutable하게 만듭니다.
  `state/kernel/<name>/active-generation`은 현재 사용할 generation 번호(없으면 `none`)를
  원자적으로 선택합니다. 회전/폐기 시 과거 export는 삭제하지 않지만 revoked key를 active로
  선택하지 않습니다. 이것은 kernel/MOK/UEFI db/keyring을 등록하거나 변경하지 않습니다.
  Intermediate를 등록했다고 미래의 모든 leaf가 자동으로 허용된다고 약속할 수 없으며,
  대상 kernel의 실제 trust 정책에서 signed module을 검증해야 합니다. Kernel의 ECDSA
  지원과 허용 curve/digest 조합은 배포판·kernel configuration마다 다르므로 대상 환경에서
  검증해야 합니다. 이 도구는 Secure Boot, MOK, UEFI db를 등록하거나 검증하지 않으며
  Secure Boot 동작 또는 module 허용을 보장하지 않습니다.

TLS/Kubernetes/code-signing은 Intermediate와 파일 경로만 분리하고 하나의 Root를
공유합니다. 따라서 shared-Root bundle은 강한 도메인 침해 격리가 아닙니다. 강한 격리가
필요하면 용도별 Root를 운영하십시오.

## 개발 검증

```sh
uv run python -m unittest discover -s tests -v
uv build
# 생성된 wheel을 깨끗한 venv에 설치한 뒤 --config /외부/policy.toml plan 으로 smoke test
```

테스트는 전부 임시 디렉터리에 실제 OpenSSL state를 만들고 지웁니다. 프로젝트 policy로
운영 인증서·credential·신뢰 저장소를 생성하거나 설치하지 않습니다.
