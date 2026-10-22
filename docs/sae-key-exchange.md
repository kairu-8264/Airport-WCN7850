# SAE key exchange development (not WPA3 connection support)

Base: 28170de153a615885c93543d3f2fc208a5bc6b63. Branch: sae-key-exchange.

Implemented prerequisites:
- SAE AKM-defined EAPOL descriptor 0 with AES-128-CMAC, AES Key Wrap, SHA256 PTK KDF, 48-byte CCMP-128 PTK and a 22-byte non-NUL KDF label.
- Receive policy rejects descriptor 0 for WPA2 and all legacy descriptors for SAE; SAE is restricted to RSN with CCMP pairwise and group ciphers. FT-SAE stays rejected.
- Existing WPA2 PSK and SHA256-PSK derivation semantics are unchanged; independent vectors cover both.
- BIP IGTK keys are routed to net80211 software crypto rather than the unsupported firmware key installer. This is a prerequisite, not tested full PMF support.
- Native SAE request diagnostics record authentication flags, key length and cipher type ONLY. No password, PMK bytes, SSID or address is added to these diagnostics.

Evidence: hostap wpa_eapol_key_mic() and wpa_pmk_to_ptk(), as imported by FreeBSD:
https://github.com/freebsd/freebsd-src/blob/main/contrib/wpa/src/common/wpa_common.c
The MIC for ordinary SAE is AES-CMAC, not the HMAC-SHA256 used by Suite B. SAE uses a different descriptor from SHA256-PSK even though both use SHA256 for PTK derivation.

Tests:
python3 scripts/test-sae-milestone.py --cxx clang++
python3 scripts/test-sae-key-exchange.py --cxx clang++

The new harness executes the production AES/CMAC/SHA1/SHA256/HMAC/RC4/key-wrap sources and selected net80211 functions with kernel include/endian adapters. It checks 288 descriptor policies, independently generated PTK and EAPOL MIC vectors, MIC tampering, RFC3394 wrap/unwrap, and invalid wrapped key data. It does not execute the full packet receive path or radio transport. Windows local testing adapts temporary-directory permissions in the test launcher because the app sandbox cannot access Python 0700 temporary directories.

NOT implemented/enabled:
- Vetted ECC/PWE backend, SAE Commit/Confirm state machine, H2E/Hunting-and-Pecking, anti-clogging, retry/cancel handling and SAE-generated PMK/PMKID lifecycle.
- Delivery of a real SAE password from the Tahoe native WCL interface. The current decoder accepts at most 32 key bytes and PMK cipher types; a WPA3 password dialog does not establish that plaintext reaches this ABI. A WPA2 PMK is not an SAE password.
- Verified PMF peer/vdev setup, unicast robust management handling, BIP RX/TX and SA Query against WCN7850 firmware.
- SAE AKM selection, SAE association RSN generation, WPA3/PMF capability advertisement or successful WPA3 network access.

The explicit SAE request rejection remains. No authentication-success stub or WPA2 fallback is introduced. This branch must not be labelled a WPA3-capable driver.

Next native observation, when booting macOS is convenient: try the WPA3 network once, then inspect only the metadata lines using:

log show --last 10m --style compact --predicate 'eventMessage CONTAINS "WCL SAE request"'

Do not send the password. If no such line appears, that is also useful: the native interface may reject or route the request before this driver entry point. AP model and WPA3-only/transition mode are still needed for an interoperability test plan. The credential interface must be established before choosing a kernel SAE engine versus a native/external supplicant bridge.
