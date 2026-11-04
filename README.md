# 可玩（PlayableSign）

基于 Feather 的签名工具。包名：`cn.kyzsalist.PlayableSign`

## 云构建

推送到 `main` 会触发 GitHub Actions 构建 IPA，产物在：

- Actions Artifact：`Feather-IPA`
- 分支：`build-artifacts` → `artifacts/Feather-latest.ipa`

```bash
git clone --depth 1 -b build-artifacts https://github.com/zb990-bit/Feather.git
```

## 本机构建

```bash
./build.sh
# → packages/Feather.ipa
```
