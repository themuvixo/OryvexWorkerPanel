with open("src/generated/ui.js", "r") as f:
    text = f.read()

# Make getInlineAssets and getPanelHtml safely handle unbundled or unreplaced RAW_ARR
safe_unpack = """
async function unpack() {
  if (_cachedAssets) return _cachedAssets;
  if (_inflight) return _inflight;
  _inflight = (async () => {
    try {
      if (!Array.isArray(RAW_ARR) || RAW_ARR === "__NL_ASSET_PLACEHOLDER__") {
        return { style: '', qr: '', skyline: '', shell: '' };
      }
      const bin = atob(RAW_ARR.join(""));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) ^ K[i & 15];
      const ds = new DecompressionStream("gzip");
      const stream = new Blob([bytes]).stream().pipeThrough(ds);
      const txt = await new Response(stream).text();
      _cachedAssets = JSON.parse(txt);
    } catch (e) {
      console.warn?.('[ui] unpack warning:', e);
      _cachedAssets = { style: '', qr: '', skyline: '', shell: '' };
    }
    _inflight = null;
    return _cachedAssets;
  })();
  return _inflight;
}
"""

# Replace unpack function in src/generated/ui.js
import re
text = re.sub(r'async function unpack\(\)\s*\{[\s\S]*?return _inflight;\s*\}', safe_unpack.strip(), text)
with open("src/generated/ui.js", "w") as f:
    f.write(text)

print("Updated src/generated/ui.js with safe fallback!")
