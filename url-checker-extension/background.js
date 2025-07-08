console.log("🚀 background.js is running");

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const visitedUrl = changeInfo.url;
    console.log("🔗 Visited URL:", visitedUrl);

    fetch('http://localhost:5000/check-url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: visitedUrl })
    })
    .then(response => response.json())
    .then(data => {
      console.log("🛡️ Backend response:", data);
      if (data.dangerous) {
        
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icon128.png',
          title: '⚠️ Dangerous Site Detected',
          message: `This site may be harmful:\n${visitedUrl}`,
          priority: 2
        });
      }
    })
    .catch(err => console.error('❌ Fetch error:', err));
  }
});
