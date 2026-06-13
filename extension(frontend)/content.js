// 1. Create the container for the hover card
const popup = document.createElement('div');
popup.className = 'chrome-link-card';

popup.innerHTML = `
  <div class="card-banner">
    <span class="banner-text">⚠️ Check If Link Is Malicious</span>
  </div>
  <div class="card-content">
    <div class="card-text">Evaluating link safety...</div>
    <button class="card-btn" id="analyse-btn">🔍 ANALYZE</button>
  </div>
`;

document.body.appendChild(popup);

let currentHoveredUrl = ""; // Track the active link URL
let currentHoveredLink = null; // Store the link element
let hideTimeout = null; // Timer for delay

// 2. Listen for mouseover events to show the popup near a link
document.addEventListener('mouseover', (event) => {
  const link = event.target.closest('a');
  
  if (link) {
    // Clear any pending hide timer
    if (hideTimeout) {
      clearTimeout(hideTimeout);
      hideTimeout = null;
    }
    
    currentHoveredUrl = link.href;
    currentHoveredLink = link; 
    popup.style.display = 'flex';
    
    // Position the popup slightly below and centered relative to the link
    const rect = link.getBoundingClientRect();
    popup.style.left = (window.scrollX + rect.left) + 'px';
    popup.style.top = (window.scrollY + rect.bottom + 8) + 'px';
    
    // Reset text for a brand new link hover
    popup.querySelector('.card-text').innerHTML = `🔗 ${currentHoveredUrl.substring(0, 40)}${currentHoveredUrl.length > 40 ? '...' : ''}`;
    popup.querySelector('#analyse-btn').innerText = "🔍 ANALYZE";
    popup.querySelector('#analyse-btn').disabled = false;
  }
});

// 3. Handle the "Analyse" click event - WITH PROPAGATION FIX
popup.querySelector('#analyse-btn').addEventListener('click', async (event) => {
  // CRITICAL: Prevent the click from reaching the underlying link
  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();
  
  if (!currentHoveredUrl) return;
  
  const btn = popup.querySelector('#analyse-btn');
  const txtDiv = popup.querySelector('.card-text');
  
  // Set button UI to loading state
  btn.innerText = "⏳ ANALYZING...";
  btn.disabled = true;

  try {
    // Connect to your Python FastAPI backend application
    const response = await fetch('YOUR RENDER URL/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: currentHoveredUrl })
    });
    
    const data = await response.json();
    
    // Update the layout with the confidence score
    if (data.is_phishing) {
       txtDiv.innerHTML = `
         <div style="border-left: 8px solid #dc3545; padding-left: 12px;">
           <div style="font-weight: 900; font-size: 18px; color: #dc3545; text-transform: uppercase;">⚠️ PHISHING DETECTED!</div>
           <div style="margin-top: 8px;">
             <span style="color:#666;">Confidence:</span>
             <strong style="color:#dc3545; font-size: 20px;">${data.confidence.toFixed(1)}%</strong>
           </div>
           <div style="margin-top: 6px; font-size: 11px; color:#666;">Do not enter any personal information</div>
         </div>
       `;
    } else {
       txtDiv.innerHTML = `
         <div style="border-left: 8px solid #28a745; padding-left: 12px;">
           <div style="font-weight: 900; font-size: 18px; color: #28a745; text-transform: uppercase;">✅ SAFE LINK</div>
           <div style="margin-top: 8px;">
             <span style="color:#666;">Confidence:</span>
             <strong style="color:#28a745; font-size: 20px;">${data.confidence.toFixed(1)}%</strong>
           </div>
           <div style="margin-top: 6px; font-size: 11px; color:#666;">This link appears legitimate</div>
         </div>
       `;
    }

    // Bring the button back to life
    btn.innerText = "✓ ANALYZED";
    btn.disabled = false;
    
    // Reset button text after 2 seconds
    setTimeout(() => {
      if (btn.innerText === "✓ ANALYZED") {
        btn.innerText = "🔍 ANALYZE";
      }
    }, 2000);

  } catch (error) {
     txtDiv.innerHTML = `
       <div style="border-left: 8px solid #dc3545; padding-left: 12px;">
         <div style="color: #dc3545; font-weight: bold;">❌ CONNECTION ERROR</div>
         <div style="font-size: 11px; margin-top: 5px;">${error.message}</div>
       </div>
     `;
     btn.innerText = "🔄 RETRY";
     btn.disabled = false;
  }
});

// Also prevent click on the popup itself from propagating
popup.addEventListener('click', (event) => {
  event.preventDefault();
  event.stopPropagation();
});

// 4. Hide the popup when the mouse leaves the link area entirely (WITH 0.5 SECOND DELAY)
document.addEventListener('mouseout', (event) => {
  const enteringElement = event.relatedTarget;
  
  // If moving to the popup itself, don't hide
  if (popup.contains(enteringElement)) return;
  
  const leavingLink = event.target.closest('a');
  if (leavingLink) {
    // Set timer to hide after 0.5 seconds
    hideTimeout = setTimeout(() => {
      popup.style.display = 'none';
    }, 500);
  }
});

// Cancel hide timer when mouse enters the popup
popup.addEventListener('mouseenter', () => {
  if (hideTimeout) {
    clearTimeout(hideTimeout);
    hideTimeout = null;
  }
});

// Hide popup when mouse leaves the popup (with delay)
popup.addEventListener('mouseleave', () => {
  hideTimeout = setTimeout(() => {
    popup.style.display = 'none';
  }, 500);
});
