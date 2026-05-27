document.addEventListener("click", (event) => {
  const anchor = event.target?.closest?.("a[href]");
  if (!anchor) return;
  const href = anchor.href || anchor.getAttribute("href");
  if (!href) return;
  if (href.startsWith("tsl://proof/") || href.includes("/p/")) {
    event.preventDefault();
    chrome.runtime.sendMessage({ type: "tsl-proof-link", href });
  }
});

const tslEnvelopePattern = /"tsl_envelope"\s*:|tsl:\/\/proof\/|\/p\/[A-Za-z0-9_-]{40,}/;
if (tslEnvelopePattern.test(document.body?.innerText ?? "")) {
  chrome.runtime.sendMessage({
    type: "tsl-page-signal",
    href: location.href,
    title: document.title
  });
}
