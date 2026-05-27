const verifierBase = "http://localhost:8090/p/";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "verify-tsl-proof",
    title: "Verify TSL proof",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== "verify-tsl-proof" || !info.linkUrl) return;
  const url = normalizeProofUrl(info.linkUrl);
  if (url) chrome.tabs.create({ url });
});

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "tsl-proof-link" && message.href) {
    const url = normalizeProofUrl(message.href);
    if (url) chrome.tabs.create({ url });
    return;
  }
  if (message?.type === "tsl-page-signal") {
    chrome.action.setBadgeText({ text: "TSL" });
    chrome.action.setBadgeBackgroundColor({ color: "#1c4f96" });
  }
});

function normalizeProofUrl(href) {
  if (href.startsWith("tsl://proof/")) return `${verifierBase}${encodeURIComponent(href.slice("tsl://proof/".length))}`;
  const index = href.indexOf("/p/");
  if (index >= 0) return `${verifierBase}${href.slice(index + 3)}`;
  return null;
}
