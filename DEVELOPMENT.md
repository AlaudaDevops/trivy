# Trivy alauda 分支开发指南

## 背景

此前，trivy 作为通用的 cli，在多个插件中都有被使用，需要各自修复 trivy 自身的漏洞。

为了避免重复工作，所以我们基于 [trivy](https://github.com/aquasecurity/trivy.git) fork 出了当前仓库，并通过 `alauda-vx.xx.xx` 分支来维护。

使用 [renovate](https://gitlab-ce.alauda.cn/devops/tech-research/renovate/-/blob/main/docs/quick-start/0002-quick-start.md) 自动修复对应版本上的漏洞。

## 仓库结构

在原有代码的基础上，添加了以下内容：

- [alauda-auto-tag.yaml](./.github/workflows/alauda-auto-tag.yaml): PR 合并到 `alauda-vx.xx.xx` 分支时，自动打 tag，并触发 goreleaser
- [release-alauda.yaml](./.github/workflows/release-alauda.yaml): 支持 tag 更新或手动触发 goreleaser（action 里自动创建 tag 时不会触发该流水线，因为 action 的设计是不会递归触发多个 action）
- [reusable-release-alauda.yaml](./.github/workflows/reusable-release-alauda.yaml): 执行 goreleaser 创建 release
- [scan-alauda.yaml](.github/workflows/scan-alauda.yaml): 执行 trivy 扫描漏洞（`rootfs` 扫描 go binary）
- [goreleaser-alauda.yml](goreleaser-alauda.yml): 发布 alauda 版本的 release 的配置文件

## 流水线

### 提 PR 时触发

- [test.yaml](.github/workflows/test.yaml): 官方的测试流水线，包含单元测试、集成测试等
- [scan-alauda.yaml](.github/workflows/scan-alauda.yaml): 执行 trivy 扫描漏洞（`rootfs` 扫描 go binary）

### 合并到 alauda-vx.xx.xx 分支时触发

- [alauda-auto-tag.yaml](.github/workflows/alauda-auto-tag.yaml): 自动打 tag，并触发 goreleaser
- [reusable-release-alauda.yaml](.github/workflows/reusable-release-alauda.yaml): 执行 goreleaser 创建 release（由 `alauda-auto-tag.yaml` 触发）

### 其他

其他官方维护的流水线没有做改动，在 Action 页面上禁用了一些无关的流水线。

## renovate 漏洞修复机制

renovate 的配置文件是 [renovate.json](https://github.com/AlaudaDevops/trivy/blob/main/renovate.json)

1. renovate 检测到分支存在漏洞，提 PR 修复
2. PR 自动执行测试
3. 所有测试通过后，renovate 自动合并 PR
4. 分支更新后，通过 action 自动打 tag（例：v0.62.1-alauda-0，patch 版本和最后一位都会递增）
5. goreleaser 基于 tag 自动发布 release

## 维护方案

当需要使用新版本的 trivy 时，按照以下步骤执行：

1. 从对应 tag 拉出 alauda 分支，例如 `v0.62.1` tag 对应 `alauda-v0.62.1` 分支
2. 将新分支加入到 renovate 的配置文件中，用于自动扫描并修复漏洞
3. renovate 提 PR 后，会自动跑流水线，若所有测试通过，则 PR 将会被自动合并
4. 合并到 `alauda-v0.62.1` 分支后，goreleaser 会自动创建出 `v0.62.2-alauda-0` release（注意：不是 `v0.62.1-alauda-0`，因为升级版本才能让 renovate 识别到）
5. 其他插件中配置的 renovate 会根据配置自动从 release 中获取制品
