let openingAppTab;

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
  const targetUrl = activeTab && /^https?:\/\//i.test(activeTab.url || "") ? activeTab.url : "";
  openOrFocusAppTab(targetUrl).catch((error) => {
    console.error("[ChainShield] Failed to open the investigation tab.", error);
  });
});
