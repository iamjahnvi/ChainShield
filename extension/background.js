let openingAppTab;

async function openOrFocusAppTab() {
  if (openingAppTab) {
    return openingAppTab;
  }

  openingAppTab = (async () => {
    const appUrl = chrome.runtime.getURL("popup.html");
    const matchingTabs = await chrome.tabs.query({ url: appUrl });
    const existingTab = matchingTabs[0];

    if (existingTab && existingTab.id !== undefined && existingTab.windowId !== undefined) {
      await chrome.windows.update(existingTab.windowId, { focused: true });
      await chrome.tabs.update(existingTab.id, { active: true });
      return;
    }

    await chrome.tabs.create({ url: appUrl, active: true });
  })();

  try {
    await openingAppTab;
  } finally {
    openingAppTab = undefined;
  }
}

chrome.action.onClicked.addListener(() => {
  openOrFocusAppTab().catch((error) => {
    console.error("[ChainShield] Failed to open the investigation tab.", error);
  });
});
