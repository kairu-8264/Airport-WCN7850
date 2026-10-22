#!/usr/bin/env python3
"""Source contracts and optional compiled tests of the production AKM parser.

python3 scripts/test-sae-milestone.py [--cxx /path/to/clang++]
No hardware, firmware, or macOS SDK is used. This is NOT a kext build.
"""
import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
NET = ROOT / 'itl80211/openbsd/net80211'


def read(path):
    return path.read_text(encoding='utf-8')


def function(source, marker):
    start = source.index(marker)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class SourceContracts(unittest.TestCase):
    def test_selector_namespaces_and_legacy_mapping(self):
        body = function(read(NET / 'ieee80211_input.c'),
                        'ieee80211_parse_rsn_akm(const u_int8_t selector[4])')
        wpa, rsn = body.split('} else if', 1)
        cases = lambda text: dict(re.findall(
            r'case\s+(\d+):[\s\S]*?return\s+(IEEE80211_AKM_\w+);', text))
        self.assertEqual(cases(wpa), {'1': 'IEEE80211_AKM_8021X', '2': 'IEEE80211_AKM_PSK'})
        self.assertEqual(cases(rsn), {
            '1': 'IEEE80211_AKM_8021X', '2': 'IEEE80211_AKM_PSK',
            '5': 'IEEE80211_AKM_SHA256_8021X', '6': 'IEEE80211_AKM_SHA256_PSK',
            '8': 'IEEE80211_AKM_SAE', '9': 'IEEE80211_AKM_FT_SAE'})
        self.assertIn('return IEEE80211_AKM_NONE;', body)

    def test_sae_is_not_a_psk_or_local_capability(self):
        header = read(NET / 'ieee80211_crypto.h')
        values = {k: int(v, 16) for k, v in re.findall(
            r'(IEEE80211_AKM_\w+)\s*=\s*(0x[0-9a-fA-F]+)', header)}
        bits = [v for v in values.values() if v]
        self.assertEqual(len(bits), len(set(bits)))
        self.assertTrue(all(v & (v - 1) == 0 for v in bits))
        for name in ('ieee80211_is_8021x_akm', 'ieee80211_is_sha256_akm'):
            self.assertNotIn('AKM_SAE', function(header, name + '('))
        # Local AKM configuration and output intentionally have no SAE path.
        for filename in ('ieee80211_ioctl.c', 'ieee80211_node.c', 'ieee80211_output.c'):
            self.assertNotRegex(read(NET / filename), r'IEEE80211_AKM_(?:FT_)?SAE')
        node = read(NET / 'ieee80211_node.c')
        self.assertIn('(ni->ni_rsnakms & ic->ic_rsnakms) == 0', node)

    def test_reject_before_state_mutation(self):
        sky = read(ROOT / 'airport/AirportItlwmSkywalkInterface.cpp')
        assoc = function(sky, 'setASSOCIATE(struct apple80211_assoc_data *ad)')
        self.assertLess(assoc.index('if (!ad)'), assoc.index('ad->ad_auth_upper'))
        self.assertLess(assoc.index('return kIOReturnUnsupported;'), assoc.index('setAUTH_TYPE('))
        direct = function(sky, 'associateSSID(uint8_t *ssid')
        self.assertLess(direct.index('return;'), direct.index('ieee80211_disable_rsn(ic)'))
        self.assertNotIn('authtype_upper |= APPLE80211_AUTHTYPE_WPA2_PSK', direct)
        wcl = function(read(ROOT / 'airport/WCL/WCL.cpp'),
                       'startWCLJoin(AirportWCL::JoinRequest &join)')
        guard = wcl[:wcl.index('auto auth =')]
        self.assertIn('APPLE80211_AUTHTYPE_WPA3_SAE |', guard)
        self.assertIn('APPLE80211_AUTHTYPE_WPA3_FT_SAE', guard)
        self.assertIn('explicit_bzero(&join, sizeof(join));', guard)
        self.assertIn('return kIOReturnUnsupported;', guard)

    def test_wcl_capabilities_remain_conservative(self):
        src = read(ROOT / 'airport/AirportItlwmV2.cpp')
        body = function(src, 'getCARD_CAPABILITIES(OSObject *object,')
        self.assertIn('memset(cd, 0, sizeof(struct apple80211_capability_data))', body)
        wcl = body.split('#ifdef AIRPORT_WCL', 1)[1].split('#else', 1)[0]
        # No newly guessed private capability bits for SAE or PMF.
        writes = re.findall(r'cd->capabilities\[(\d+)\]\s*[|&]?=', wcl)
        self.assertEqual(set(writes), {'0', '1', '2', '5', '17'})


def native_test(cxx):
    header = read(NET / 'ieee80211_crypto.h')
    enum = re.search(r'enum ieee80211_akm\s*\{.*?\};', header, re.S).group()
    parser = function(read(NET / 'ieee80211_input.c'),
                      'ieee80211_parse_rsn_akm(const u_int8_t selector[4])')
    # Extract only security helpers, avoiding unrelated platform wire structs.
    wcl = read(ROOT / 'airport/WCL/WCL.hpp')
    helpers = ['namespace AirportWCL {',
               re.search(r'struct JoinRequest\s*\{.*?\};', wcl, re.S).group(),
               re.search(r'enum class LegacyAuth\s*\{.*?\};', wcl, re.S).group()]
    for name in ('read16', 'validIEs', 'selectWPA2TransitionMode',
                 'validRSNOverride', 'isPassphrase', 'classifyLegacyAuth'):
        match = re.search(r'inline\s+\w+\s+' + name + r'\(', wcl)
        helpers.append(function(wcl, match.group()))
    helpers.append('}')
    source = r'''
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <initializer_list>
typedef uint8_t u_int8_t;
#define MICROSOFT_OUI "\x00\x50\xf2"
#define IEEE80211_OUI "\x00\x0f\xac"
''' + '\n'.join(helpers) + '\n' + enum + '\nenum ieee80211_akm\n' + parser + r'''
int main() {
    // Real WCL classifier: preserve WPA2 and reject explicit SAE bitmasks.
    AirportWCL::JoinRequest join = {};
    join.lowerAuth = 1;
    join.upperAuth = 1u << 3;
    join.keyLength = 32;
    join.keyCipher = 6;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Personal);
    for (unsigned auth : {1u << 12, 1u << 13, (1u << 3) | (1u << 12)}) {
        join.upperAuth = auth;
        assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Invalid);
    }
    // Scan-copy transformation must preserve pure SAE and PMF-required APs.
    uint8_t transition[] = {48,24,1,0,0,15,172,4,1,0,0,15,172,4,
                           2,0,0,15,172,2,0,15,172,8,0x80,0};
    uint8_t copy[sizeof(transition)];
    memcpy(copy, transition, sizeof(copy));
    assert(AirportWCL::selectWPA2TransitionMode(copy, sizeof(copy)) == sizeof(copy)-4);
    assert(copy[14] == 1 && copy[19] == 2 && copy[20] == 0x80);
    memcpy(copy, transition, sizeof(copy));
    copy[24] = 0xc0;
    assert(AirportWCL::selectWPA2TransitionMode(copy, sizeof(copy)) == sizeof(copy));
    assert(copy[14] == 2 && copy[23] == 8 && copy[24] == 0xc0);
    uint8_t pure[] = {48,20,1,0,0,15,172,4,1,0,0,15,172,4,
                     1,0,0,15,172,8,0xc0,0};
    uint8_t saved[sizeof(pure)];
    memcpy(saved, pure, sizeof(pure));
    assert(AirportWCL::selectWPA2TransitionMode(pure, sizeof(pure)) == sizeof(pure));
    assert(memcmp(saved, pure, sizeof(pure)) == 0);
    const unsigned char ouis[][3] = {{0,15,172}, {0,80,242}, {1,15,172}};
    for (unsigned o = 0; o < 3; ++o) {
        for (unsigned type = 0; type < 256; ++type) {
            uint8_t s[] = {ouis[o][0], ouis[o][1], ouis[o][2], uint8_t(type)};
            int want = 0;
            if (o < 2 && type == 1) want = IEEE80211_AKM_8021X;
            if (o < 2 && type == 2) want = IEEE80211_AKM_PSK;
            if (o == 0 && type == 5) want = IEEE80211_AKM_SHA256_8021X;
            if (o == 0 && type == 6) want = IEEE80211_AKM_SHA256_PSK;
            if (o == 0 && type == 8) want = IEEE80211_AKM_SAE;
            if (o == 0 && type == 9) want = IEEE80211_AKM_FT_SAE;
            if (int(ieee80211_parse_rsn_akm(s)) != want) return 1;
        }
    }
    puts("PASS: 768 production AKM selector cases and WCL WPA2/SAE fixtures");
}
'''
    with tempfile.TemporaryDirectory(prefix='sae-test-', dir=ROOT) as folder:
        path = pathlib.Path(folder)
        (path / 'test.cpp').write_text(source, encoding='utf-8')
        exe = path / 'test.exe'
        if pathlib.Path(cxx).name.lower() in ('cl', 'cl.exe'):
            # Existing WCL IE-length byte update is bounded by its RSN checks.
            # MSVC warns on its size_t subtraction; keep other warnings fatal.
            command = [cxx, '/nologo', '/std:c++14', '/W3', '/WX', '/wd4267', '/EHsc',
                       '/I' + str(ROOT), str(path / 'test.cpp'), '/Fe:' + str(exe)]
        else:
            command = [cxx, '-std=c++14', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT),
                       str(path / 'test.cpp'), '-o', str(exe)]
        if sys.platform == 'darwin':
            # Calling the clang++ binary directly bypasses xcrun SDK selection.
            sdk = subprocess.check_output(
                ['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
            command += ['-isysroot', sdk]
        subprocess.run(command, check=True, cwd=path)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--cxx')
    opts = args.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SourceContracts))
    if not result.wasSuccessful():
        raise SystemExit(1)
    compiler = opts.cxx or shutil.which('clang++') or shutil.which('g++')
    if compiler:
        native_test(compiler)
    else:
        print('SKIP: native parser tests (no C++ compiler); source contracts only')
