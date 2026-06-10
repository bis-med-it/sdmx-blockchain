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

def ensure_single_placeholder(root: etree._Element, ns_uri: str) -> etree._Element:
    # Ensure exactly one <message:Source>Transaction Hash:</message:Source> exists in the Header.
    # If there is any non-empty Transaction Hash (i.e. already anchored), raise error.
    # If multiple empty placeholders exist, keep the first and remove the rest.
    # If none exist, create a single placeholder as the last child of Header.
    # Returns the placeholder element that should be used.
    header = root.find(f".//{{{ns_uri}}}Header")
    if header is None:
        raise HTTPException(status_code=400, detail="<message:Header> not found in XML.")

    source_xpath = f".//{{{ns_uri}}}Source"
    placeholders = []
    filled = []

    for tag in header.findall(source_xpath):
        text = (tag.text or "").strip()
        if text.lower().startswith("transaction hash:"):
            value = text[len("Transaction Hash:"):].strip()
            if value:
                filled.append(tag)
            else:
                placeholders.append(tag)

    if len(filled) > 0:
        # File already contains a non-empty Transaction Hash -> do not re-publish
        raise HTTPException(status_code=400, detail="File already contains a Transaction Hash.")

    # If there are multiple empty placeholders, keep the first and remove others
    if len(placeholders) >= 1:
        keeper = placeholders[0]
        # remove subsequent placeholders
        for extra in placeholders[1:]:
            parent = extra.getparent()
            if parent is not None:
                parent.remove(extra)
    else:
        # create a new placeholder deterministically as last child of header
        keeper = etree.SubElement(header, f"{{{ns_uri}}}Source")
        keeper.text = "Transaction Hash:"

    # Normalize the keeper's text to exact placeholder
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


def _len32_be(b: bytes) -> bytes:
    return len(b).to_bytes(4, byteorder="big")


def merkle_root_from_hex_hashes(hex_hashes: list[str]) -> str:
    # Implements the domain-separated leaf/node construction from the paper.
    # Input: list of hex-encoded 512-bit hashes (uppercase/lowercase OK).
    # Output: hex-encoded root (uppercase)
    if not hex_hashes:
        raise ValueError("No hashes provided for Merkle root")

    # Convert each underlying h (hex) to raw bytes
    leaves: list[bytes] = []
    for h in hex_hashes:
        h_bytes = bytes.fromhex(h)
        leaf = compute_sha3_512_raw(b"\x00" + _len32_be(h_bytes) + h_bytes)
        leaves.append(leaf)

    # Build tree
    nodes = leaves
    while len(nodes) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            combined = b"\x01" + _len32_be(left) + left + _len32_be(right) + right
            parent = compute_sha3_512_raw(combined)
            next_level.append(parent)
        nodes = next_level

    root = nodes[0]
    return root.hex().upper()