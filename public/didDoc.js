// public/didDoc.js
// Browser-side DID Doc fetch

export async function generateDidDoc() {
  try {
  
    const resp = await fetch("/.well-known/did.json");
    if (!resp.ok) {
      throw new Error(`Failed to fetch DID Doc: ${resp.status} ${resp.statusText}`);
    }
    const didDoc = await resp.json();
    return didDoc;
  } catch (err) {
    console.error("Error fetching DID Doc:", err);
    throw err;
  }
}
// ===== server.js =====
// Express server with DID Doc endpoint


