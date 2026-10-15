# CSI MakLock QA update distribution

This repository contains test installers, signed update metadata, and distribution automation. CSI MakLock application source remains in the private development repository.

The revised 1.1.6 build 115 candidate is prepared for an owner-controlled test release. Staging does not change the live 1.1.5 update channel. The earlier unpublished build 113 and 114 candidates is retained in private artifact history.

When the private handoff confirms validation and staging are complete, open Releases, edit the draft named **CSI MakLock 1.1.6 QA, build 115**, and click **Publish release**. Wait for **Release approved CSI MakLock 1.1.6** to finish successfully before checking for updates on your test Macs.

Publication activates the signed package at the address already trusted by installed 1.1.5 apps. The original 1.1.5 package and signed metadata remain archived. This is a QA test, not a production release.

Build 115 includes the original-resolution approved artwork and clearer Settings password and offline-update messages. Local macOS 26.6.2 compilation, model checks, compiled-artwork checks, packaging, and both CPU slices passed. The new candidate still needs visual acceptance and runtime testing on the Intel macOS 15 Mac.

Human Gatekeeper, administrator prompts, physical Watch/Touch ID behavior, and visual acceptance still require testing on real Macs.
