import hashlib
from fastapi import HTTPException
import lxml.etree as etree
import time
from functools import wraps

# lxml.etree provides libxml2's canonicalization (C14N). That normalizes namespace declarations, attribute ordering, 
# whitespace (with the right parser options), etc., producing an identical byte stream for semantically-equivalent XML.
# Inserting/normalizing the Transaction Hash: placeholder before canonicalization guarantees that both variants 
# (with or without placeholder) produce the same canonical bytes — therefore the same hash.


def time_execution(func):
    @wraps(func)
    def time_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        print(f"Function {func.__name__} took {total_time:.4f} seconds")
        return result
    return time_wrapper

# Domain-separation identifier that marks a <message:Source> element as an SJI
# blockchain anchor (as opposed to a Source carrying unrelated provenance text).
# Per the paper (Section 4.1), every anchor descriptor and every embedded VC is
# injected as a <message:Source> carrying sourceID="sji:anchor".
SJI_ANCHOR_SOURCE_ID = "sji:anchor"


def strip_anchor(root: etree._Element, ns_uri: str) -> etree._Element:
    # Idempotent anchor-stripping projection strip_{anchor}(X): remove EVERY
    # <message:Source> element carrying sourceID="sji:anchor", regardless of its
    # content (anchor descriptor or VC). The whole-file fingerprint therefore
    # commits to the statistical payload alone, independently of anchor history,
    # so a file may be (re-)anchored any number of times deterministically.
    # Mutates and returns the given root.
    for src in root.findall(f".//{{{ns_uri}}}Source"):
        if src.get("sourceID") == SJI_ANCHOR_SOURCE_ID:
            parent = src.getparent()
            if parent is not None:
                parent.remove(src)
    return root


def add_anchor_source(header: etree._Element, ns_uri: str, text: str) -> etree._Element:
    # Append a new anchor-tagged <message:Source sourceID="sji:anchor"> element.
    el = etree.SubElement(header, f"{{{ns_uri}}}Source")
    el.set("sourceID", SJI_ANCHOR_SOURCE_ID)
    el.text = text
    return el


def find_anchor_sources(header: etree._Element, ns_uri: str) -> list[etree._Element]:
    # Return all anchor-tagged <message:Source> elements under the given header.
    return [
        src
        for src in header.findall(f".//{{{ns_uri}}}Source")
        if src.get("sourceID") == SJI_ANCHOR_SOURCE_ID
    ]


def ensure_single_placeholder(root: etree._Element, ns_uri: str) -> etree._Element:
    # DEPRECATED / retained for backward compatibility only.
    # The paper's model (Section 4.1) replaces the "reject-on-re-anchor"
    # placeholder scheme with the idempotent strip_anchor projection above, which
    # permits deterministic re-anchoring. New code should call strip_anchor() and
    # add_anchor_source() instead of this helper.
    header = root.find(f".//{{{ns_uri}}}Header")
    if header is None:
        raise HTTPException(status_code=400, detail="<message:Header> not found in XML.")
    keeper = etree.SubElement(header, f"{{{ns_uri}}}Source")
    keeper.set("sourceID", SJI_ANCHOR_SOURCE_ID)
    keeper.text = "Transaction Hash:"
    return keeper

@time_execution
def canonicalize_xml_bytes(xml_bytes: bytes, exclusive: bool = True, with_comments: bool = False) -> bytes:
    # Canonicalize XML bytes using C14N. exclusive=True gives Exclusive C14N (recommended for XML fragments with namespaces). with_comments=False omits comments from canonicalization.
    # Returns canonical bytes (no XML declaration).

    # Parse with lxml (preserves namespaces)
    parser = etree.XMLParser(remove_blank_text=True)  # removes ignorable indentation text nodes
    root = etree.fromstring(xml_bytes, parser=parser)

    # etree.tostring supports method='c14n' and accepts exclusive/with_comments
    c14n_bytes = etree.tostring(root, method="c14n", exclusive=exclusive, with_comments=with_comments)
    return c14n_bytes

@time_execution
def compute_sha3_512_bytes(data: bytes) -> str:
    # Uppercase hex to preserve digests
    return hashlib.sha3_512(data).hexdigest().upper()


def compute_sha3_512_raw(data: bytes) -> bytes:
    # Return raw digest bytes (64 bytes)
    return hashlib.sha3_512(data).digest()

@time_execution
def compute_sha3_512_c14n(xml_bytes: bytes, exclusive: bool = True, with_comments: bool = False) -> str:
    # Canonicalize and hash the XML bytes. Accepts full XML Bytes
    c14n = canonicalize_xml_bytes(xml_bytes, exclusive=exclusive, with_comments=with_comments)
    return compute_sha3_512_bytes(c14n)

def message_namespace(root: etree._Element) -> str:
    # root.tag looks like "{uri}LocalName"
    if root.tag.startswith("{"):
        return root.tag.split("}")[0].strip("{")
    raise HTTPException(status_code=400, detail="Cannot detect message namespace")

def find_source_tags_in_header(root: etree._Element, ns_uri: str):
    # Return list of <Source> elements under Header (lxml elements).
    header = root.find(f".//{{{ns_uri}}}Header")
    if header is None:
        raise HTTPException(status_code=400, detail="<message:Header> not found in XML.")
    return header.findall(f".//{{{ns_uri}}}Source"), header


def compute_series_hash(series_element: etree._Element, exclusive: bool = True, with_comments: bool = False) -> str:
    # Canonicalize a single <Series> element and return SHA3-512 hex (uppercase)
    # Serialize the element to bytes and canonicalize using the existing helper
    ser_bytes = etree.tostring(series_element, encoding="utf-8")
    c14n = canonicalize_xml_bytes(ser_bytes, exclusive=exclusive, with_comments=with_comments)
    return compute_sha3_512_bytes(c14n)


def _len32_be_int(n: int) -> bytes:
    # 32-bit big-endian encoding of the integer n (the leaf count), per the paper.
    return int(n).to_bytes(4, byteorder="big")


def _merkle_leaf(h_bytes: bytes) -> bytes:
    # H_leaf(h) = SHA3-512(0x00 || h)   (Section 4.1, "Domain separation")
    return compute_sha3_512_raw(b"\x00" + h_bytes)


def _merkle_node(left: bytes, right: bytes) -> bytes:
    # H_node(L, R) = SHA3-512(0x01 || L || R)
    return compute_sha3_512_raw(b"\x01" + left + right)


def merkle_root_from_hex_hashes(hex_hashes: list[str]) -> str:
    # Implements the domain-separated leaf/node/root construction from the paper
    # (Section 4.1). Because leaves and internal nodes are all fixed-length
    # 64-byte SHA3-512 outputs, the single-byte domain separators alone prevent
    # concatenation ambiguity; length prefixing is NOT applied to leaves/nodes.
    # The final root wraps the internal root with a domain-separated layer that
    # explicitly binds the leaf count n:
    #     R = SHA3-512(0x02 || len32(n) || R_internal).
    # For n = 1 no padding is needed (the tree is a single leaf).
    # Input:  list of hex-encoded 512-bit hashes (case-insensitive).
    # Output: hex-encoded root (uppercase).
    if not hex_hashes:
        raise ValueError("No hashes provided for Merkle root")

    n = len(hex_hashes)

    # Leaves L_i = H_leaf(h_i)
    leaves: list[bytes] = [_merkle_leaf(bytes.fromhex(h)) for h in hex_hashes]

    # Internal root: single leaf needs no padding; otherwise pad to the next
    # power of two by duplicating the final leaf, forming a perfect binary tree.
    nodes = leaves
    while len(nodes) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            next_level.append(_merkle_node(left, right))
        nodes = next_level

    root_internal = nodes[0]

    # Domain-separated root wrapper binding the leaf count n.
    root = compute_sha3_512_raw(b"\x02" + _len32_be_int(n) + root_internal)
    return root.hex().upper()


def merkle_inclusion_proof(hex_hashes: list[str], index: int) -> list[tuple[str, str]]:
    # Generate an inclusion proof pi_i for the leaf at position `index` over the
    # ordered leaf fingerprints `hex_hashes` (Section 4.2). The proof is the ordered
    # list of sibling node values together with an orientation bit indicating on
    # which side the sibling sits ('L' = sibling is left, 'R' = sibling is right),
    # so the root recomputation via H_node is unambiguous. Padding follows the
    # paper's scheme: odd levels duplicate the final node before pairing.
    if not hex_hashes:
        raise ValueError("No hashes provided for inclusion proof")
    if not (0 <= index < len(hex_hashes)):
        raise ValueError("Leaf index out of range")

    nodes = [_merkle_leaf(bytes.fromhex(h)) for h in hex_hashes]
    proof: list[tuple[str, str]] = []
    idx = index
    while len(nodes) > 1:
        # Pad to an even count by duplicating the final node (perfect-tree scheme).
        if len(nodes) % 2 == 1:
            nodes = nodes + [nodes[-1]]
        sib = idx ^ 1
        orientation = "R" if sib > idx else "L"
        proof.append((nodes[sib].hex().upper(), orientation))
        nodes = [_merkle_node(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
        idx //= 2
    return proof


def root_from_inclusion_proof(leaf_hex: str, proof: list[tuple[str, str]], n: int) -> str:
    # Recompute the domain-separated Merkle root R from a leaf fingerprint and its
    # inclusion proof (Section 4.2). Applies H_leaf to the fingerprint, folds in the
    # ordered siblings via H_node respecting orientation bits, then wraps the
    # internal root with the leaf-count-binding layer: R = SHA3-512(0x02||len32(n)||R_int).
    cur = _merkle_leaf(bytes.fromhex(leaf_hex))
    for sib_hex, orientation in proof:
        sib = bytes.fromhex(sib_hex)
        if orientation == "R":
            cur = _merkle_node(cur, sib)
        elif orientation == "L":
            cur = _merkle_node(sib, cur)
        else:
            raise ValueError(f"Invalid orientation bit: {orientation!r}")
    root = compute_sha3_512_raw(b"\x02" + _len32_be_int(n) + cur)
    return root.hex().upper()