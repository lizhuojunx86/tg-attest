"""
tg-attest.eutl_build —— 构建 EU 可信列表快照。**需要 [eutl] 额外依赖。**

与 eutl.py 的分工，以及为什么切在这里：
    eutl.py    查询，零依赖，跑在写入路径上。
    eutl_build 构建，要下载约 26 MB XML、验 30 份 XAdES 签名、解析上千条
               服务条目，几十秒起步。离线跑，产出一份纯 JSON 快照。

    生产决策热路径上不可能做这些事。把「取回并验证可信列表」和「查一下
    这把公钥当时合不合格」当成同一件事，是这个功能最容易犯的架构错误。

信任链（两级，任何一级不验都等于没验）：
    1. LOTL 的签名证书必须在 OJ C/2026/1944 公布的那 6 张证书之内。
       本模块**只钉死这 6 个 SHA-256 摘要**，证书本身从 LOTL 自带的
       自指指针里取，取到后逐一比对摘要。钉摘要而不是钉证书，是为了让
       信任根小到可以让人用眼睛跟官方公报核对——6 行十六进制，
       任何人都能自己查一遍，这正是不变量 3 要的效果。
    2. 各成员国列表的签名证书必须在 LOTL 里为该国登记的证书之内。

    不验签的可信列表不是信任根，是一份从 HTTPS 上下载的 XML。把传输层
    当信任根，正是 docs/fail-open-audit.md 在批的那类错误。

已知会静默出错的地方，都踩过：
  - enveloped-signature 变换要*省略* Signature 元素，但不省略它后面的
    文本节点。lxml 的 remove() 连 tail 一起删，于是签名者把换行放在
    Signature.tail 上的那些列表（荷兰）摘要对不上，而把换行放在前一个
    兄弟节点 tail 上的（德国、奥地利）却能过。同一份代码，一半国家能验
    一半不能，且不报错——只是"验签失败"。见 _drop_preserving_tail。
  - MimeType 在 additionaltypes 命名空间，不在主命名空间。
  - DigitalId 里的 X509Certificate 在 TSL 命名空间，**不是** xmldsig 命名空间。
  - 命名空间前缀（ns2..ns6 / xades / ...）各国不一致，一律按 URI 绑定。
  - ServiceHistoryInstance 里几乎从不带证书（TS 119 612 5.6.3 明确"to the
    exception of any certificate"），所以证书匹配只能对 ServiceInformation
    做，历史只用来查"某时刻是什么状态"。
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .eutl import (
    NON_QUALIFIED_TSA_STIS,
    QTST_STI,
    SNAPSHOT_SPEC,
    _parse_dt,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 信任根
# ---------------------------------------------------------------------------
# OJ C/2026/1944（2026-04-15）公布的 6 张 LOTL 签名证书的 SHA-256。
# 该公报明文取代 OJ C 276, 16.8.2019。
#   https://eur-lex.europa.eu/eli/C/2026/1944/oj
# 这 6 行是本功能唯一的信任锚。核对方式：打开上面的公报，把每张证书的
# "SHA-256 digest (hexadecimal) value" 与这里逐字比对。
LOTL_SIGNING_CERT_SHA256 = frozenset({
    "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
    "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
    "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
    "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
    "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
    "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
})

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
OJ_REFERENCE = "https://eur-lex.europa.eu/eli/C/2026/1944/oj"

TSL_NS = "http://uri.etsi.org/02231/v2#"
ADD_NS = "http://uri.etsi.org/02231/v2/additionaltypes#"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
EXC_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"

ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
EXC_C14N_WC = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

TSL_MIME_XML = "application/vnd.etsi.tsl+xml"

# TS 119 612 5.3.1：TLv6 起该值应为 "6"。CID (EU) 2025/2164 自 2026-04-29
# 适用，没有共存期。认不出的版本要吵，不要默默按老格式解析。
EXPECTED_TSL_VERSION = "6"


def _T(tag: str) -> str:
    return f"{{{TSL_NS}}}{tag}"


def _D(tag: str) -> str:
    return f"{{{DS_NS}}}{tag}"


class TrustedListError(Exception):
    pass


# ---------------------------------------------------------------------------
# XAdES 验签
# ---------------------------------------------------------------------------
# 密码学不手写（不变量 2）：签名运算交给 cryptography，排除式 c14n 交给
# lxml，本模块只负责把 CID (EU) 2025/2164 要求的引用/变换形状卡死。
# 那条形状要求不是形式主义——它堵的是变换注入：允许任意 Transform 链，
# 攻击者就能构造一个"签的是文档的某个子集"的签名，而摘要照样对得上。

def _digest_algs():
    from cryptography.hazmat.primitives import hashes
    return {
        "http://www.w3.org/2001/04/xmlenc#sha256": hashes.SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384": hashes.SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512": hashes.SHA512,
    }


def _sig_algs():
    from cryptography.hazmat.primitives import hashes
    return {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": (hashes.SHA256, False),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": (hashes.SHA384, False),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": (hashes.SHA512, False),
        # 德国用的是 RSASSA-PSS。不支持它就等于漏掉德国。
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": (hashes.SHA256, True),
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": (hashes.SHA384, True),
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": (hashes.SHA512, True),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": (hashes.SHA256, False),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": (hashes.SHA384, False),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": (hashes.SHA512, False),
    }


def _parser():
    from lxml import etree
    # 这些 XML 是从网上下载的、尚未验签的数据。实体展开与外部取值一律关掉。
    return etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)


def _c14n(el, prefixes=None) -> bytes:
    from lxml import etree
    return etree.tostring(el, method="c14n", exclusive=True,
                          with_comments=False, inclusive_ns_prefixes=prefixes)


def _prefix_list(transform):
    if transform is None:
        return None
    inc = transform.find(f"{{{EXC_NS}}}InclusiveNamespaces")
    if inc is None:
        return None
    return (inc.get("PrefixList") or "").split() or None


def _drop_preserving_tail(el) -> None:
    """执行 enveloped-signature 变换：移除 el，但**保留它后面的文本节点**。

    规范说这个变换省略的是 Signature 元素及其子树，不包括紧跟其后的文本。
    lxml 的 remove() 会把 tail 一起删掉，于是签名者恰好把换行放在
    Signature.tail 上时，规范化后的字节就少了一个换行，摘要对不上。

    实测：荷兰的列表 Signature.tail == '\\n'，删了就验不过；德国、奥地利
    的同一个换行落在前一个兄弟节点的 tail 上，删不删都一样。也就是说，
    漏掉这个函数的实现会在一部分成员国上静默失败，而症状是"这个国家
    的可信列表验签不通过"，看上去像对方的问题。
    """
    tail = el.tail
    parent = el.getparent()
    prev = el.getprevious()
    parent.remove(el)
    if tail:
        if prev is not None:
            prev.tail = (prev.tail or "") + tail
        else:
            parent.text = (parent.text or "") + tail


@dataclass
class SignatureCheck:
    ok: bool
    signer_der: bytes | None
    signer_sha256: str | None
    detail: str


def verify_tsl_signature(xml_bytes: bytes, trusted_cert_sha256: frozenset[str]) -> SignatureCheck:
    """验证一份可信列表（LOTL 或成员国列表）的 enveloped XAdES 签名。

    通过的条件全部满足才算：
      1. 恰好一个 Signature，且是根元素的直接子元素
      2. 恰好一个 URI="" 的 Reference，其 Transforms 恰好两个、顺序为
         enveloped-signature 然后 exc-c14n（CID (EU) 2025/2164 附件第 3 点）
      3. 该 Reference 的摘要与规范化后的文档一致
      4. 其余 Reference（XAdES SignedProperties）的摘要一致，且不得指向外部
      5. SignedInfo 上的签名用 KeyInfo 里的证书验证通过
      6. 该证书的 SHA-256 在给定的可信集合内
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from lxml import etree

    DIG, SIG = _digest_algs(), _sig_algs()
    try:
        root = etree.fromstring(xml_bytes, _parser())
    except Exception as e:                       # noqa: BLE001
        return SignatureCheck(False, None, None, f"XML 解析失败：{type(e).__name__}: {e}")

    sigs = root.findall(_D("Signature"))
    if len(sigs) != 1:
        return SignatureCheck(False, None, None,
                              f"根元素下应恰好有 1 个 Signature，实际 {len(sigs)}")
    sig = sigs[0]
    si = sig.find(_D("SignedInfo"))
    if si is None:
        return SignatureCheck(False, None, None, "Signature 缺 SignedInfo")

    # ---- 2. 引用与变换形状 ----
    refs = si.findall(_D("Reference"))
    doc_refs = [r for r in refs if (r.get("URI") or "") == ""]
    if len(doc_refs) != 1:
        return SignatureCheck(False, None, None,
                              f'应恰好有 1 个 URI="" 的 Reference，实际 {len(doc_refs)}')
    dref = doc_refs[0]
    tsets = dref.findall(_D("Transforms"))
    if len(tsets) != 1:
        return SignatureCheck(False, None, None,
                              f"该 Reference 应恰好有 1 个 Transforms，实际 {len(tsets)}")
    tl = tsets[0].findall(_D("Transform"))
    algs = [t.get("Algorithm") for t in tl]
    if len(tl) != 2 or algs[0] != ENVELOPED or algs[1] not in (EXC_C14N, EXC_C14N_WC):
        return SignatureCheck(False, None, None,
                              f"变换链不符合 CID (EU) 2025/2164 的要求：{algs}")

    # ---- 3. 文档摘要 ----
    root2 = etree.fromstring(xml_bytes, _parser())
    _drop_preserving_tail(root2.findall(_D("Signature"))[0])
    dm = dref.find(_D("DigestMethod"))
    if dm is None or dm.get("Algorithm") not in DIG:
        return SignatureCheck(False, None, None,
                              f"不认识的摘要算法：{dm.get('Algorithm') if dm is not None else None}")
    h = hashes.Hash(DIG[dm.get("Algorithm")]())
    h.update(_c14n(root2, _prefix_list(tl[1])))
    if base64.b64encode(h.finalize()).decode() != (dref.find(_D("DigestValue")).text or "").strip():
        return SignatureCheck(False, None, None, "文档摘要与 Reference 不一致")

    # ---- 4. 其余引用 ----
    by_id = {}
    for el in root.iter():
        for k in ("Id", "id", "ID"):
            v = el.get(k)
            if v:
                by_id.setdefault(v, el)
    for r in refs:
        uri = r.get("URI") or ""
        if uri == "":
            continue
        if not uri.startswith("#"):
            return SignatureCheck(False, None, None, f"不允许外部引用：{uri}")
        target = by_id.get(uri[1:])
        if target is None:
            return SignatureCheck(False, None, None, f"引用目标不存在：{uri}")
        ts = r.find(_D("Transforms"))
        pl = _prefix_list(ts.findall(_D("Transform"))[-1]) if ts is not None and len(ts) else None
        dm2 = r.find(_D("DigestMethod")).get("Algorithm")
        if dm2 not in DIG:
            return SignatureCheck(False, None, None, f"不认识的摘要算法：{dm2}")
        h2 = hashes.Hash(DIG[dm2]())
        h2.update(_c14n(target, pl))
        if base64.b64encode(h2.finalize()).decode() != (r.find(_D("DigestValue")).text or "").strip():
            return SignatureCheck(False, None, None, f"引用 {uri} 摘要不一致")

    # ---- 5. SignedInfo 签名 ----
    cm = si.find(_D("CanonicalizationMethod"))
    if cm is None or cm.get("Algorithm") not in (EXC_C14N, EXC_C14N_WC):
        return SignatureCheck(False, None, None,
                              f"SignedInfo 规范化方法不受支持：{cm.get('Algorithm') if cm is not None else None}")
    sm = si.find(_D("SignatureMethod")).get("Algorithm")
    if sm not in SIG:
        return SignatureCheck(False, None, None, f"不认识的签名算法：{sm}")
    hash_cls, is_pss = SIG[sm]
    si_octets = _c14n(si, _prefix_list(cm))
    sigval = base64.b64decode("".join((sig.find(_D("SignatureValue")).text or "").split()))

    certs = []
    for e in sig.iter(_D("X509Certificate")):
        try:
            certs.append(base64.b64decode("".join((e.text or "").split())))
        except Exception:                        # noqa: BLE001
            continue
    if not certs:
        return SignatureCheck(False, None, None, "KeyInfo 里没有 X509Certificate")

    last = "没有证书通过验证"
    for der in certs:
        try:
            cert = x509.load_der_x509_certificate(der)
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                if is_pss:
                    pub.verify(sigval, si_octets,
                               padding.PSS(mgf=padding.MGF1(hash_cls()),
                                           salt_length=hash_cls.digest_size),
                               hash_cls())
                else:
                    pub.verify(sigval, si_octets, padding.PKCS1v15(), hash_cls())
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                from cryptography.hazmat.primitives.asymmetric.utils import (
                    encode_dss_signature,
                )
                n = len(sigval) // 2
                pub.verify(encode_dss_signature(int.from_bytes(sigval[:n], "big"),
                                                int.from_bytes(sigval[n:], "big")),
                           si_octets, ec.ECDSA(hash_cls()))
            else:
                last = f"不支持的密钥类型 {type(pub).__name__}"
                continue
        except InvalidSignature:
            last = "签名值与 SignedInfo 不符"
            continue
        except Exception as e:                   # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
            continue

        # ---- 6. 签名者必须在可信集合内 ----
        fp = hashlib.sha256(der).hexdigest()
        if fp not in trusted_cert_sha256:
            return SignatureCheck(False, der, fp,
                                  f"签名证书 {fp[:16]}… 不在可信集合内（该集合共 "
                                  f"{len(trusted_cert_sha256)} 张）")
        return SignatureCheck(True, der, fp, f"验签通过（{sm.rsplit('#', 1)[-1]}）")

    return SignatureCheck(False, None, None, last)


# ---------------------------------------------------------------------------
# 抓取
# ---------------------------------------------------------------------------

def fetch(url: str, *, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(url, headers={
        # 意大利对非浏览器 UA 返回 403。这不是规范要求的，但现实如此。
        "User-Agent": "Mozilla/5.0 (compatible; tg-attest/eutl)",
        "Accept": "application/xml,text/xml,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


@dataclass
class Pointer:
    cc: str
    url: str
    tsl_type: str | None
    cert_sha256: frozenset[str]
    certs: tuple[bytes, ...]


def parse_lotl_pointers(xml_bytes: bytes) -> list[Pointer]:
    """从 LOTL 里取出各成员国列表的位置与签名证书。

    选 XML 指针只能按 MimeType，不能按扩展名：丹麦发布的是
    `TSLDK_v6xml`（没有点），捷克用 `.xtsl`，塞浦路斯是个 Lotus Notes
    的 URL 带 `$file/`。按 `.xml` 结尾过滤会漏掉它们。
    """
    from lxml import etree
    root = etree.fromstring(xml_bytes, _parser())
    out: list[Pointer] = []
    for p in root.iter(_T("OtherTSLPointer")):
        info = {c.tag.split("}")[-1]: c
                for oi in p.findall(f"{_T('AdditionalInformation')}/{_T('OtherInformation')}")
                for c in oi}
        mime = info.get("MimeType")
        if mime is None:
            mime = p.find(f".//{{{ADD_NS}}}MimeType")
        if mime is None or (mime.text or "").strip() != TSL_MIME_XML:
            continue
        terr = info.get("SchemeTerritory")
        loc = p.find(_T("TSLLocation"))
        if terr is None or loc is None:
            continue
        # DigitalId 里的 X509Certificate 在 TSL 命名空间，不是 xmldsig。
        ders = []
        for e in p.iter(_T("X509Certificate")):
            try:
                ders.append(base64.b64decode("".join((e.text or "").split())))
            except Exception:                    # noqa: BLE001
                continue
        tt = info.get("TSLType")
        out.append(Pointer(
            cc=(terr.text or "").strip(),
            url=(loc.text or "").strip(),
            tsl_type=(tt.text or "").strip() if tt is not None else None,
            cert_sha256=frozenset(hashlib.sha256(d).hexdigest() for d in ders),
            certs=tuple(ders),
        ))
    return out


# ---------------------------------------------------------------------------
# 解析成员国列表
# ---------------------------------------------------------------------------

def _names(el, tag: str) -> tuple[str, ...]:
    """取多语言 <Name xml:lang="xx"> 的**全部**变体。

    PRO-4.6.4-08 要拿证书的 O= 和 TSP 名称比对。只取英文变体会在
    只发布本国语言名称的成员国上产生假阴性。
    """
    if el is None:
        return ()
    seen, out = set(), []
    for n in el.iter(_T("Name")):
        t = (n.text or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return tuple(out)


@dataclass
class ParsedList:
    cc: str
    tsl_version: str | None
    sequence_number: str | None
    issue_date: str | None
    next_update: str | None
    services: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_trusted_list(xml_bytes: bytes, cc: str) -> ParsedList:
    """解析一份成员国可信列表，抽出全部 TSA 家族服务条目及其状态历史。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from lxml import etree

    root = etree.fromstring(xml_bytes, _parser())
    si = root.find(_T("SchemeInformation"))

    def _txt(parent, tag):
        e = parent.find(_T(tag)) if parent is not None else None
        return (e.text or "").strip() if e is not None and e.text else None

    out = ParsedList(
        cc=cc,
        tsl_version=_txt(si, "TSLVersionIdentifier"),
        sequence_number=_txt(si, "TSLSequenceNumber"),
        issue_date=_txt(si, "ListIssueDateTime"),
        next_update=None,
    )
    nu = si.find(f"{_T('NextUpdate')}/{_T('dateTime')}") if si is not None else None
    if nu is not None and nu.text:
        out.next_update = nu.text.strip()

    if out.tsl_version != EXPECTED_TSL_VERSION:
        out.warnings.append(
            f"TSLVersionIdentifier={out.tsl_version!r}，期望 {EXPECTED_TSL_VERSION!r}"
            "（TLv6 自 2026-04-29 起适用，无共存期）")

    idx = 0
    for tsp in root.iter(_T("TrustServiceProvider")):
        tspi = tsp.find(_T("TSPInformation"))
        tsp_names = tuple(dict.fromkeys(
            _names(tspi.find(_T("TSPName")) if tspi is not None else None, "Name")
            + _names(tspi.find(_T("TSPTradeName")) if tspi is not None else None, "Name")))
        for svc in tsp.iter(_T("TSPService")):
            info = svc.find(_T("ServiceInformation"))
            if info is None:
                continue
            sti = _txt(info, "ServiceTypeIdentifier")
            if sti != QTST_STI and sti not in NON_QUALIFIED_TSA_STIS:
                continue                          # 只留 TSA 家族，其余跳过

            sdi = info.find(_T("ServiceDigitalIdentity"))
            der = None
            for e in (sdi.iter(_T("X509Certificate")) if sdi is not None else ()):
                try:
                    der = base64.b64decode("".join((e.text or "").split()))
                    break
                except Exception:                # noqa: BLE001
                    continue
            if der is None:
                # 没有证书就无法做公钥匹配。记一条警告而不是悄悄丢掉——
                # "少了一条目"和"这条目不合格"在结果上看不出区别。
                out.warnings.append(f"{tsp_names[:1]} 的一条 {sti} 条目没有 X509Certificate，已跳过")
                continue
            try:
                cert = x509.load_der_x509_certificate(der)
            except Exception as e:               # noqa: BLE001
                out.warnings.append(f"证书解析失败并跳过：{type(e).__name__}: {e}")
                continue

            spki = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            subject_der = cert.subject.public_bytes()

            # ---- 状态时间线 ----
            cur_status = _txt(info, "ServiceStatus")
            cur_start = _txt(info, "StatusStartingTime")
            hist: list[tuple[str, str]] = []
            for hi in svc.iter(_T("ServiceHistoryInstance")):
                hs = _txt(hi, "ServiceStatus")
                ht = _txt(hi, "StatusStartingTime")
                if hs and ht:
                    hist.append((ht, hs))
            # TS 119 612 5.5.10：历史按时间**降序**存放。规范同时要求
            # (PRO-4.3.4-03A) 校验顺序，乱序或时刻重复要报错而不是重排——
            # 因为那意味着这份列表本身不可信。这里降级为警告并排序，
            # 但警告会进快照，不会被吞掉。
            desc = [_parse_dt(t) for t, _ in hist]
            if any(desc[i] < desc[i + 1] for i in range(len(desc) - 1)):
                out.warnings.append(f"{tsp_names[:1]} 的一条 {sti} 条目历史顺序不符合降序要求")
            if len({d.isoformat() for d in desc}) != len(desc):
                out.warnings.append(f"{tsp_names[:1]} 的一条 {sti} 条目历史存在重复时刻")

            timeline = sorted(hist, key=lambda kv: _parse_dt(kv[0]))
            if cur_status and cur_start:
                timeline.append((cur_start, cur_status))
            timeline = [(_parse_dt(t).astimezone(timezone.utc).isoformat(), s)
                        for t, s in timeline]
            if not timeline:
                out.warnings.append(f"{tsp_names[:1]} 的一条 {sti} 条目没有任何状态时间点，已跳过")
                continue

            idx += 1
            out.services.append({
                "ref": f"{cc}:{out.sequence_number}:{idx:04d}",
                "cc": cc,
                "sti": sti,
                "tsp_names": list(tsp_names),
                "subject_str": cert.subject.rfc4514_string(),
                "subject_der_sha256": hashlib.sha256(subject_der).hexdigest(),
                "spki_sha256": hashlib.sha256(spki).hexdigest(),
                "spki_der_b64": base64.b64encode(spki).decode(),
                "is_ca": _is_ca(cert),
                "history": [list(x) for x in timeline],
            })
    return out


def _is_ca(cert) -> bool:
    from cryptography import x509
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except Exception:                            # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# 构建快照
# ---------------------------------------------------------------------------

def build_snapshot(*, lotl_url: str = LOTL_URL, timeout: float = 60.0,
                   only: tuple[str, ...] | None = None,
                   qtst_only: bool = True) -> dict:
    """下载并验证 LOTL 与各成员国列表，产出快照 dict。

    任何一国失败都不会中断整体构建：失败的国家进 `unavailable`，查询时
    对该国返回 None（未查）而不是 False（不合格）。把一次网络故障固化成
    法律结论，是这个功能最危险的失败方式——爱尔兰和葡萄牙在实测中就
    连不上，这不是假设。
    """
    built_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lotl_bytes = fetch(lotl_url, timeout=timeout)
    chk = verify_tsl_signature(lotl_bytes, LOTL_SIGNING_CERT_SHA256)
    if not chk.ok:
        # LOTL 验不过就必须停。没有 LOTL 就没有各国列表的信任根，
        # 继续下去构建出来的东西只是一堆下载来的 XML。
        raise TrustedListError(
            f"LOTL 验签失败，拒绝构建快照：{chk.detail}。"
            f"信任根为 OJ C/2026/1944 公布的 {len(LOTL_SIGNING_CERT_SHA256)} 张证书"
            f"（{OJ_REFERENCE}）")

    pointers = parse_lotl_pointers(lotl_bytes)
    from lxml import etree
    lroot = etree.fromstring(lotl_bytes, _parser())
    lsi = lroot.find(_T("SchemeInformation"))
    lseq = lsi.find(_T("TSLSequenceNumber")) if lsi is not None else None
    lissue = lsi.find(_T("ListIssueDateTime")) if lsi is not None else None

    snap: dict = {
        "spec": SNAPSHOT_SPEC,
        "built_at": built_at,
        "lotl": {
            "url": lotl_url,
            "sha256": hashlib.sha256(lotl_bytes).hexdigest(),
            "sequence_number": (lseq.text or "").strip() if lseq is not None else None,
            "issue_date": (lissue.text or "").strip() if lissue is not None else None,
            "signer_sha256": chk.signer_sha256,
            "oj_reference": OJ_REFERENCE,
        },
        "territories": {},
        "unavailable": {},
        "warnings": [],
        "services": [],
    }

    for p in pointers:
        # EU 自指指针不是成员国列表，它承载的是 LOTL 签名证书本身。
        if p.cc == "EU" or (p.tsl_type or "").endswith("EUlistofthelists"):
            continue
        if only and p.cc not in only:
            continue
        if not p.cert_sha256:
            snap["unavailable"][p.cc] = "LOTL 未为该国登记签名证书"
            continue
        try:
            raw = fetch(p.url, timeout=timeout)
        except Exception as e:                   # noqa: BLE001
            snap["unavailable"][p.cc] = f"下载失败 {type(e).__name__}: {e}"
            log.warning("EUTL %s 下载失败：%s", p.cc, e)
            continue

        c = verify_tsl_signature(raw, p.cert_sha256)
        if not c.ok:
            snap["unavailable"][p.cc] = f"验签失败：{c.detail}"
            log.warning("EUTL %s 验签失败：%s", p.cc, c.detail)
            continue

        try:
            parsed = parse_trusted_list(raw, p.cc)
        except Exception as e:                   # noqa: BLE001
            snap["unavailable"][p.cc] = f"解析失败 {type(e).__name__}: {e}"
            continue

        svcs = [s for s in parsed.services
                if (s["sti"] == QTST_STI or not qtst_only)]
        snap["territories"][p.cc] = {
            "url": p.url,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "tsl_version": parsed.tsl_version,
            "sequence_number": parsed.sequence_number,
            "issue_date": parsed.issue_date,
            "next_update": parsed.next_update,
            "signer_sha256": c.signer_sha256,
            "service_count": len(svcs),
        }
        snap["services"].extend(svcs)
        for w in parsed.warnings:
            snap["warnings"].append(f"{p.cc}: {w}")
        log.info("EUTL %s：%d 条 %s 条目", p.cc, len(svcs),
                 "QTST" if qtst_only else "TSA 家族")

    return snap


def write_snapshot(snap: dict, path: str) -> str:
    """写盘。键排序、禁 float（本快照没有浮点字段），换行结尾。

    排序不是为了好看：快照是可以被 diff 的运维产物，键序不稳定会让
    "这次构建变了什么"变得读不出来。
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    return path


# ---------------------------------------------------------------------------
# 命令行：python -m tg_attest.eutl_build -o eutl.json
# ---------------------------------------------------------------------------
# 刻意做成独立入口，不挂到 tg_attest.cli 下面：那个命令是给审计方用的
# 披露包验证器，位置参数就是披露包路径，README 里写死了这个用法。
# 为了加一个运维命令去改它的调用约定不划算。

def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="python -m tg_attest.eutl_build",
        description="构建 EU 可信列表快照，供写入路径做盖戳时点的合格性判定")
    p.add_argument("-o", "--out", default="eutl_snapshot.json", help="输出路径")
    p.add_argument("--only", help="只取这些成员国，逗号分隔，如 DE,FR,IT")
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--all-tsa-types", action="store_true",
                   help="连非合格的 TSA 家族条目一并收录（默认只收 QTST）")
    p.add_argument("-q", "--quiet", action="store_true")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.WARNING if a.quiet else logging.INFO,
                        format="%(message)s")
    snap = build_snapshot(
        timeout=a.timeout,
        only=tuple(x.strip().upper() for x in a.only.split(",")) if a.only else None,
        qtst_only=not a.all_tsa_types)
    write_snapshot(snap, a.out)

    n_terr, n_svc = len(snap["territories"]), len(snap["services"])
    print(f"\n快照已写入 {a.out}")
    print(f"  成员国 {n_terr} 个，服务条目 {n_svc} 条")
    print(f"  LOTL 序号 {snap['lotl']['sequence_number']}，"
          f"摘要 {snap['lotl']['sha256'][:16]}…")
    if snap["unavailable"]:
        # 这一段必须打出来，而且不能只在 -v 下打。取不到的成员国在查询时
        # 一律返回「未查」，使用者有权知道自己的覆盖面缺了哪几块。
        print(f"  ⚠ 未能取得 {len(snap['unavailable'])} 个成员国的列表，"
              f"对这些国家的 TSA 将返回「未查」而非「不合格」：")
        for cc, why in sorted(snap["unavailable"].items()):
            print(f"      {cc}: {why[:100]}")
    if snap["warnings"]:
        print(f"  ⚠ {len(snap['warnings'])} 条解析警告（见快照内 warnings 字段）")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
