const verifierBase = "http://localhost:8090/p/";
const input = document.getElementById("proof");
const status = document.getElementById("status");

document.getElementById("open").addEventListener("click", async () => {
  const value = input.value.trim();
  const url = normalizeProofUrl(value);
  if (!url) {
    status.textContent = "Paste a TSL proof link first.";
    return;
  }
  await chrome.tabs.create({ url });
  window.close();
});

function normalizeProofUrl(href) {
  if (href.startsWith("tsl://proof/")) return `${verifierBase}${encodeURIComponent(href.slice("tsl://proof/".length))}`;
  const index = href.indexOf("/p/");
  if (index >= 0) return `${verifierBase}${href.slice(index + 3)}`;
  if (/^[A-Za-z0-9_-]+$/.test(href)) return `${verifierBase}${href}`;
  return null;
}
