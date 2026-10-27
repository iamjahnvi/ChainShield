let openingAppTab;
let lastActiveWebsiteUrl = "";

function supportedWebsiteUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url) ? url : "";
}

async function getActiveWebsiteUrl(clickedTab) {
  const clickedUrl = supportedWebsiteUrl(clickedTab && clickedTab.url);
  if (clickedUrl) {
    lastActiveWebsiteUrl = clickedUrl;
    return clickedUrl;
  }

  try {
    const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const activeUrl = supportedWebsiteUrl(activeTab && activeTab.url);
    if (activeUrl) {
      lastActiveWebsiteUrl = activeUrl;
      return activeUrl;
    }
  } catch (error) {
    console.warn("[ChainShield] Could not read the active tab URL.", error);
  }

  return lastActiveWebsiteUrl;
}

async function openOrFocusAppTab(targetUrl) {
  if (openingAppTab) {
    return openingAppTab;
  }

  openingAppTab = (async () => {
    const appUrl = chrome.runtime.getURL("popup.html");
    const matchingTabs = await chrome.tabs.query({ url: `${appUrl}*` });
    const existingTab = matchingTabs[0];
    const destination = new URL(appUrl);
    if (targetUrl) destination.searchParams.set("target", targetUrl);

    if (existingTab && existingTab.id !== undefined && existingTab.windowId !== undefined) {
      await chrome.windows.update(existingTab.windowId, { focused: true });
      await chrome.tabs.update(existingTab.id, { active: true, url: destination.href });
      return;
    }

    await chrome.tabs.create({ url: destination.href, active: true });
  })();

  try {
    await openingAppTab;
  } finally {
    openingAppTab = undefined;
  }
}

chrome.action.onClicked.addListener((activeTab) => {
  getActiveWebsiteUrl(activeTab)
    .then((targetUrl) => openOrFocusAppTab(targetUrl))
    .catch((error) => {
      console.error("[ChainShield] Failed to open the investigation tab.", error);
    });
});
