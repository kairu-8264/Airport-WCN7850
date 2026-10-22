#!/usr/bin/env python3
"""Execute production PTK/MIC/key-wrap code; no wireless or SAE auth simulation."""
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
NET = ROOT / 'itl80211/openbsd/net80211'
CRYPTO = ROOT / 'itl80211/openbsd/crypto'


def read(p):
    return p.read_text(encoding='utf-8')


def function(source, marker):
    start = source.index(marker)
    pos = source.index('{', start)
    depth, end = 1, pos + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def no_includes(source):
    return re.sub(r'^\s*#include[^\n]*\n', '\n', source, flags=re.M)


def main(cxx):
    vectors = json.loads(read(ROOT / 'tests/sae-key-vectors.json'))
    prelude = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#ifdef _MSC_VER
#define __attribute__(x)
#endif
#define __packed
#define XYLog(...) do {} while (0)
#define _KASSERT(x) assert(x)
#define NBBY 8
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif
#undef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#define bzero(p,n) memset((p),0,(n))
#define bcopy(s,d,n) memmove((d),(s),(n))
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
typedef unsigned int u_int;
typedef unsigned char u8;
typedef unsigned char u_char;
typedef char *caddr_t;
static inline uint32_t test_swap32(uint32_t x) {
    return ((x&255)<<24)|((x&65280)<<8)|((x>>8)&65280)|(x>>24);
}
static inline uint64_t test_swap64(uint64_t x) {
    return (uint64_t(test_swap32(uint32_t(x)))<<32)|test_swap32(uint32_t(x>>32));
}
#define _OSSwapInt32 test_swap32
#define _OSSwapInt64 test_swap64
#ifndef htobe64
#define htobe64 test_swap64
#endif
#ifndef htole16
#define htole16(x) (x)
#endif
static inline unsigned test_be16(const uint8_t *p) {return (unsigned(p[0])<<8)|p[1];}
static inline void test_put16(uint8_t *p,unsigned n) {p[0]=uint8_t(n>>8);p[1]=uint8_t(n);}
#define BE_READ_2 test_be16
#define BE_WRITE_2 test_put16
static inline void test_zero(void *p,size_t n) {
    volatile uint8_t *v=static_cast<volatile uint8_t *>(p);
    while(n--) *v++=0;
}
#define explicit_bzero test_zero
static inline int test_compare(const void *a,const void *b,size_t n) {
    const uint8_t *x=static_cast<const uint8_t *>(a),*y=static_cast<const uint8_t *>(b);
    uint8_t diff=0; while(n--) diff|=*x++ ^ *y++; return diff;
}
#define timingsafe_bcmp test_compare
'''
    headers = ''.join(no_includes(read(CRYPTO / (n + '.h')))
                      for n in ('aes','cmac','sha1','sha2','md5','hmac','arc4','key_wrap'))
    header = read(NET / 'ieee80211_crypto.h')
    policy = '\n'.join(re.search(r'enum ' + n + r'\s*\{.*?\};', header, re.S).group()
                       for n in ('ieee80211_cipher','ieee80211_akm'))
    for name in ('ieee80211_is_sha256_akm','ieee80211_uses_sha256_ptk',
                 'ieee80211_eapol_key_version','ieee80211_eapol_key_version_valid'):
        policy += '\nstatic inline int\n' + function(header, name + '(')
    wire = read(NET / 'ieee80211.h')
    structures = '#define EAPOL_KEY_NONCE_LEN 32\n#define EAPOL_KEY_IV_LEN 16\n#define EAPOL_KEY_MIC_LEN 16\n#define IEEE80211_ADDR_LEN 6\n#define IEEE80211_PMK_LEN 32\n#define IEEE80211_ELEMID_VENDOR 221\n'
    for name in ('ieee80211_eapol_key','ieee80211_ptk'):
        structures += re.search(r'struct ' + name + r'\s*\{.*?\}\s*__packed;', wire, re.S).group() + '\n'
    structures += 'struct ieee80211com {uint8_t ic_globalcnt[32];};\n'
    src = read(NET / 'ieee80211_crypto.c')
    production = re.search(r'typedef union _ANY_CTX\s*\{.*?\}\s*ANY_CTX;', src, re.S).group()
    for name in ('ieee80211_prf','ieee80211_kdf','ieee80211_derive_ptk',
                 'ieee80211_eapol_key_mic','ieee80211_eapol_key_check_mic',
                 'ieee80211_eapol_key_encrypt','ieee80211_eapol_key_decrypt'):
        match = re.search(r'(?:void|int)\s*\n' + name + r'\(', src)
        production += '\n' + function(src, match.group())
    tests = r'''
static void hex(const char *s,uint8_t *out) {
    for(size_t i=0;s[2*i];++i) {unsigned n=0; assert(sscanf(s+2*i,"%2x",&n)==1);out[i]=uint8_t(n);}
}
int main() {
    const ieee80211_akm akms[]={IEEE80211_AKM_PSK,IEEE80211_AKM_8021X,
        IEEE80211_AKM_SHA256_PSK,IEEE80211_AKM_SHA256_8021X,IEEE80211_AKM_SAE,IEEE80211_AKM_FT_SAE,
        ieee80211_akm(IEEE80211_AKM_SAE|IEEE80211_AKM_PSK),
        ieee80211_akm(IEEE80211_AKM_FT_SAE|IEEE80211_AKM_PSK),
        ieee80211_akm(IEEE80211_AKM_SAE|IEEE80211_AKM_FT_SAE)};
    const ieee80211_cipher ciphers[]={IEEE80211_CIPHER_CCMP,IEEE80211_CIPHER_TKIP};
    unsigned cases=0;
    for(auto akm:akms) for(auto pair:ciphers) for(auto group:ciphers) for(unsigned ver=0;ver<8;ver++) {
        bool want=false;
        if(akm==IEEE80211_AKM_SAE) want=pair==IEEE80211_CIPHER_CCMP&&group==IEEE80211_CIPHER_CCMP&&ver==0;
        else if(akm & (IEEE80211_AKM_SAE|IEEE80211_AKM_FT_SAE)) want=false;
        else if(ver>=1&&ver<=3) {
            if(akm==IEEE80211_AKM_SHA256_PSK||akm==IEEE80211_AKM_SHA256_8021X) want=ver==3;
            else if(pair==IEEE80211_CIPHER_CCMP||group==IEEE80211_CIPHER_CCMP) want=ver==2;
            else want=true;
        }
        assert(bool(ieee80211_eapol_key_version_valid(akm,pair,group,ver))==want); ++cases;
    }
    uint8_t pmk[32],aa[6],spa[6],an[32],sn[32],expected[64];
    ieee80211_ptk ptk,reverse;
'''
    for field,var in (('pmk','pmk'),('aa','aa'),('spa','spa'),('anonce','an'),('snonce','sn')):
        tests += f'hex("{vectors[field]}",{var});\n'
    for akm,expected in (('IEEE80211_AKM_SAE','sae_ptk48'),
                         ('IEEE80211_AKM_PSK','legacy_psk_ptk64'),
                         ('IEEE80211_AKM_SHA256_PSK','legacy_sha256_ptk64')):
        length = len(vectors[expected]) // 2
        tests += f'''memset(&ptk,0xaa,sizeof(ptk));
            ieee80211_derive_ptk({akm},pmk,aa,spa,an,sn,&ptk);
            hex("{vectors[expected]}",expected);
            assert(memcmp(&ptk,expected,{length})==0);
            ieee80211_derive_ptk({akm},pmk,spa,aa,sn,an,&reverse);
            assert(memcmp(&ptk,&reverse,sizeof(ptk))==0);
'''
        if length == 48:
            tests += 'for(unsigned i=16;i<32;i++) assert(ptk.tk[i]==0);\n'
    tests += 'uint8_t kck[16]; hex("' + vectors['mic_key'] + '",kck);\n'
    for entry in vectors['mic']:
        tests += '''{
            ieee80211_eapol_key frame;
            hex("%s",reinterpret_cast<uint8_t *>(&frame));
            ieee80211_eapol_key_mic(&frame,kck);
            hex("%s",expected); assert(memcmp(frame.mic,expected,16)==0);
            assert(ieee80211_eapol_key_check_mic(&frame,kck)==0);
            frame.nonce[0]^=1;
            assert(ieee80211_eapol_key_check_mic(&frame,kck)!=0);
        }
''' % (entry['frame'],entry['expected'])
    tests += 'uint8_t kek[16],plain[16],wrapped[24],reference[24],decoded[16];\n'
    for key,var in (('wrap_kek','kek'),('wrap_plaintext','plain'),('wrap_ciphertext','reference')):
        tests += f'hex("{vectors[key]}",{var});\n'
    tests += r'''
    aes_key_wrap_ctx wrap;
    aes_key_wrap_set_key(&wrap,kek,16);
    aes_key_wrap(&wrap,plain,2,wrapped);
    assert(memcmp(wrapped,reference,24)==0);
    assert(aes_key_unwrap(&wrap,wrapped,decoded,2)==0);
    assert(memcmp(decoded,plain,16)==0);
    alignas(8) uint8_t storage[256]={};
    auto frame=reinterpret_cast<ieee80211_eapol_key *>(storage);
    memcpy(frame+1,plain,16);
    BE_WRITE_2(frame->info,EAPOL_KEY_DESC_AKM);
    BE_WRITE_2(frame->paylen,16);
    ieee80211com ic={};
    ieee80211_eapol_key_encrypt(&ic,frame,kek);
    assert(BE_READ_2(frame->paylen)==24);
    assert(memcmp(frame+1,reference,24)==0);
    assert(ieee80211_eapol_key_decrypt(frame,kek)==0);
    assert(memcmp(frame+1,plain,16)==0);
    memcpy(frame+1,reference,24);
    storage[sizeof(*frame)+23]^=1;
    assert(ieee80211_eapol_key_decrypt(frame,kek)!=0);
    BE_WRITE_2(frame->paylen,15);
    assert(ieee80211_eapol_key_decrypt(frame,kek)!=0);
    printf("PASS: %u descriptor policies; SAE/WPA2 PTKs; MIC tampering; RFC3394 and SAE wrap/unwrap\n",cases);
}
'''
    with tempfile.TemporaryDirectory(prefix='sae-keys-',dir=ROOT) as folder:
        folder = pathlib.Path(folder)
        (folder/'compat.hpp').write_text(prelude+headers+policy+'\n'+structures,encoding='utf-8')
        paths = []
        for name in ('aes','cmac','sha1','sha2','md5','hmac','arc4','key_wrap'):
            path = folder/(name+'.cpp')
            path.write_text('#include "compat.hpp"\n'+no_includes(read(CRYPTO/(name+'.c'))),encoding='utf-8')
            paths.append(str(path))
        main = folder/'test.cpp'
        main.write_text('#include "compat.hpp"\n'+production+tests,encoding='utf-8')
        paths.append(str(main))
        exe = folder/'test.exe'
        if pathlib.Path(cxx).name.lower() in ('cl','cl.exe'):
            command = [cxx,'/nologo','/std:c++14','/O2','/EHsc','/W3','/wd4267','/wd4244','/wd4146',*paths,'/Fe:'+str(exe)]
        else:
            command = [cxx,'-std=c++14','-O2','-fno-strict-aliasing',*paths,'-o',str(exe)]
        if sys.platform == 'darwin':
            sdk = subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
            command += ['-isysroot',sdk]
        subprocess.run(command,check=True,cwd=folder)
        subprocess.run([str(exe)],check=True,cwd=folder)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx')
    opts = parser.parse_args()
    compiler = opts.cxx or shutil.which('clang++') or shutil.which('g++')
    if not compiler:
        parser.error('C++ compiler required: crypto tests must not be skipped')
    main(compiler)
