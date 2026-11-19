(function () {
  "use strict";

  const BASE_TITLE = "CO3094 P2P Chat";
  const PEERS_POLL_MS = 2000;
  const MESSAGES_POLL_MS = 1500;

  const state = {
    username: null,
    p2pIp: "",
    p2pPort: null,
    activeChannel: { type: "global", id: "global" },
    activePeers: {},      // { username: { ip, port, last_seen } }
    connectedPeers: {},   // { "ip:port": { username, ip, port } }
    messages: {
      global: [],
      private: {},        // { peerKey: [msg, ...] }
    },
    seenCounts: {
      global: 0,
      private: {},        // { peerKey: number }
    },
    unreadCounts: {
      global: 0,
      private: {},        // { peerKey: number }
    },
    peersTimerId: null,
    messagesTimerId: null,
    titleBlinkTimerId: null,
    titleBlinkState: false,
    toastTimerId: null,
    initialMessagesLoaded: false,
  };

  // DOM references
  const loginOverlay = document.getElementById("loginOverlay");
  const loginForm = document.getElementById("loginForm");
  const loginUsername = document.getElementById("loginUsername");
  const loginPassword = document.getElementById("loginPassword");
  const loginError = document.getElementById("loginError");
  const loginSubmitBtn = document.getElementById("loginSubmitBtn");

  const chatApp = document.getElementById("chatApp");
  const selfAvatar = document.getElementById("selfAvatar");
  const selfUsername = document.getElementById("selfUsername");
  const selfP2pInfo = document.getElementById("selfP2pInfo");
  const logoutBtn = document.getElementById("logoutBtn");

  const channelsList = document.getElementById("channelsList");
  const activePeersList = document.getElementById("activePeersList");
  const activePeerCount = document.getElementById("activePeerCount");

  const activeChannelTitle = document.getElementById("activeChannelTitle");
  const activeChannelSubtitle = document.getElementById("activeChannelSubtitle");
  const statusToast = document.getElementById("statusToast");
  const messagesContainer = document.getElementById("messagesContainer");
  const messageForm = document.getElementById("messageForm");
  const fileInput = document.getElementById("fileInput");
  const messageInput = document.getElementById("messageInput");
  const sendBtn = document.getElementById("sendBtn");

  const transferProgressBox = document.getElementById("transferProgressBox");
  const transferFileName = document.getElementById("transferFileName");
  const transferStatusBadge = document.getElementById("transferStatusBadge");
  const transferBarFill = document.getElementById("transferBarFill");
  let progressHideTimerId = null;

  function formatFileSize(bytes) {
    const size = Number(bytes) || 0;
    if (size < 1024) {
      return size + " B";
    }
    if (size < 1024 * 1024) {
      return (size / 1024).toFixed(1) + " KB";
    }
    return (size / (1024 * 1024)).toFixed(2) + " MB";
  }

  function updateProgressBar(filename, percent, statusText, statusClass) {
    if (!transferProgressBox) {
      return;
    }
    if (progressHideTimerId) {
      clearTimeout(progressHideTimerId);
      progressHideTimerId = null;
    }
    const clamped = Math.max(0, Math.min(100, Number(percent) || 0));
    transferProgressBox.classList.remove("hidden");
    transferFileName.textContent = filename || "File transfer";
    transferBarFill.style.width = clamped + "%";
    transferStatusBadge.textContent = statusText || clamped + "%";
    transferStatusBadge.classList.remove("verified", "error");
    if (statusClass) {
      transferStatusBadge.classList.add(statusClass);
    }
  }

  function scheduleHideProgressBar(delayMs) {
    if (progressHideTimerId) {
      clearTimeout(progressHideTimerId);
    }
    progressHideTimerId = setTimeout(function () {
      if (transferProgressBox) {
        transferProgressBox.classList.add("hidden");
      }
    }, delayMs || 4500);
  }

  function readFileAsBase64(file) {
    return new Promise(function (resolve, reject) {
      const reader = new FileReader();
      reader.onload = function () {
        const result = String(reader.result || "");
        const commaIdx = result.indexOf(",");
        resolve(commaIdx !== -1 ? result.slice(commaIdx + 1) : result);
      };
      reader.onerror = function () {
        reject(new Error("Không thể đọc file từ trình duyệt"));
      };
      reader.readAsDataURL(file);
    });
  }

  function showToast(text, isError) {
    if (state.toastTimerId) {
      clearTimeout(state.toastTimerId);
    }
    statusToast.textContent = text;
    statusToast.classList.remove("hidden", "error");
    if (isError) {
      statusToast.classList.add("error");
    }
    state.toastTimerId = setTimeout(function () {
      statusToast.classList.add("hidden");
    }, 3500);
  }

  function formatTimestamp(rawTs) {
    if (!rawTs) {
      return "";
    }
    const date = new Date(rawTs);
    if (Number.isNaN(date.getTime())) {
      return String(rawTs);
    }
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function getTotalUnreadCount() {
    let total = state.unreadCounts.global || 0;
    const privateKeys = Object.keys(state.unreadCounts.private);
    for (let i = 0; i < privateKeys.length; i += 1) {
      total += state.unreadCounts.private[privateKeys[i]] || 0;
    }
    return total;
  }

  function updateTitleBlink() {
    const totalUnread = getTotalUnreadCount();
    if (totalUnread > 0 && !state.titleBlinkTimerId) {
      state.titleBlinkTimerId = setInterval(function () {
        const count = getTotalUnreadCount();
        if (count <= 0) {
          stopTitleBlink();
          return;
        }
        state.titleBlinkState = !state.titleBlinkState;
        document.title = state.titleBlinkState
          ? "(" + count + ") Tin nhắn mới! - " + BASE_TITLE
          : BASE_TITLE;
      }, 800);
    } else if (totalUnread <= 0) {
      stopTitleBlink();
    }
  }

  function stopTitleBlink() {
    if (state.titleBlinkTimerId) {
      clearInterval(state.titleBlinkTimerId);
      state.titleBlinkTimerId = null;
    }
    state.titleBlinkState = false;
    document.title = BASE_TITLE;
  }

  function normalizePeersPayload(rawPeers) {
    const map = {};
    if (Array.isArray(rawPeers)) {
      for (let i = 0; i < rawPeers.length; i += 1) {
        const item = rawPeers[i];
        if (item && item.username) {
          map[item.username] = {
            ip: item.ip,
            port: item.port,
            last_seen: item.last_seen,
          };
        }
      }
    } else if (rawPeers && typeof rawPeers === "object") {
      const names = Object.keys(rawPeers);
      for (let i = 0; i < names.length; i += 1) {
        const uname = names[i];
        const info = rawPeers[uname];
        if (info && typeof info === "object") {
          map[uname] = info;
        }
      }
    }
    return map;
  }

  function resolvePeerEndpoint(peerKey) {
    if (state.activePeers[peerKey]) {
      return state.activePeers[peerKey];
    }
    const connKeys = Object.keys(state.connectedPeers);
    for (let i = 0; i < connKeys.length; i += 1) {
      const entry = state.connectedPeers[connKeys[i]];
      if (entry.username === peerKey || connKeys[i] === peerKey) {
        return entry;
      }
    }
    if (peerKey.indexOf(":") !== -1) {
      const parts = peerKey.split(":");
      const port = parseInt(parts[1], 10);
      if (!Number.isNaN(port)) {
        return { ip: parts[0], port: port, username: peerKey };
      }
    }
    return null;
  }

  function isPeerConnected(peerKey) {
    const connKeys = Object.keys(state.connectedPeers);
    for (let i = 0; i < connKeys.length; i += 1) {
      const entry = state.connectedPeers[connKeys[i]];
      if (entry && (entry.username === peerKey || connKeys[i] === peerKey)) {
        return true;
      }
    }
    return false;
  }

  function updateComposerState() {
    if (state.activeChannel.type === "global") {
      messageInput.disabled = false;
      if (fileInput) {
        fileInput.disabled = false;
      }
      sendBtn.disabled = false;
      messageInput.placeholder = "Nhập tin nhắn và nhấn Enter để gửi...";
      activeChannelSubtitle.textContent =
        "Gửi tin nhắn quảng bá và lưu trữ trên Tracker Server";
      return;
    }

    const peerKey = state.activeChannel.id;
    const connected = isPeerConnected(peerKey);
    const endpoint = resolvePeerEndpoint(peerKey);
    if (!connected) {
      messageInput.disabled = true;
      if (fileInput) {
        fileInput.disabled = true;
      }
      sendBtn.disabled = true;
      messageInput.placeholder = "Hãy bấm Connect ở Active Peers để chat với " + peerKey + "...";
      activeChannelSubtitle.textContent =
        "Chưa kết nối P2P — Bấm nút Connect để kết nối và đồng bộ tin nhắn với " + peerKey;
    } else {
      messageInput.disabled = false;
      if (fileInput) {
        fileInput.disabled = false;
      }
      sendBtn.disabled = false;
      messageInput.placeholder = "Nhập tin nhắn và nhấn Enter để gửi...";
      activeChannelSubtitle.textContent = endpoint
        ? "Đã kết nối P2P 1-1 tới " + endpoint.ip + ":" + endpoint.port
        : "Đã kết nối P2P 1-1";
    }
  }

  function isChannelActive(type, id) {
    return state.activeChannel.type === type && state.activeChannel.id === id;
  }

  function selectChannel(type, id) {
    state.activeChannel = { type: type, id: id };

    if (type === "global") {
      state.unreadCounts.global = 0;
      activeChannelTitle.textContent = "# Global Broadcast";
    } else {
      state.unreadCounts.private[id] = 0;
      if (!state.messages.private[id]) {
        state.messages.private[id] = [];
      }
      activeChannelTitle.textContent = "@ " + id;
    }

    updateComposerState();
    updateTitleBlink();
    renderChannels();
    renderActivePeers();
    renderMessages(true);
    if (!messageInput.disabled) {
      messageInput.focus();
    }
  }

  function renderChannels() {
    channelsList.innerHTML = "";

    // Always render #Global Broadcast
    const globalItem = document.createElement("li");
    globalItem.className =
      "nav-item" + (isChannelActive("global", "global") ? " active" : "");
    globalItem.addEventListener("click", function () {
      selectChannel("global", "global");
    });

    const globalLabel = document.createElement("span");
    globalLabel.className = "nav-label";
    globalLabel.textContent = "# Global Broadcast";
    globalItem.appendChild(globalLabel);

    const globalUnread = state.unreadCounts.global || 0;
    if (globalUnread > 0) {
      const badge = document.createElement("span");
      badge.className = "unread-badge";
      badge.textContent = String(globalUnread);
      globalItem.appendChild(badge);
    }
    channelsList.appendChild(globalItem);

    // Render 1-1 private channels
    const privatePeers = Object.keys(state.messages.private).sort();
    for (let i = 0; i < privatePeers.length; i += 1) {
      const peerKey = privatePeers[i];
      const item = document.createElement("li");
      item.className =
        "nav-item" + (isChannelActive("private", peerKey) ? " active" : "");
      item.addEventListener("click", function () {
        selectChannel("private", peerKey);
      });

      const label = document.createElement("span");
      label.className = "nav-label";
      label.textContent = "@ " + peerKey;
      item.appendChild(label);

      const unread = state.unreadCounts.private[peerKey] || 0;
      if (unread > 0) {
        const badge = document.createElement("span");
        badge.className = "unread-badge";
        badge.textContent = String(unread);
        item.appendChild(badge);
      }
      channelsList.appendChild(item);
    }
  }

  function renderActivePeers() {
    const peerNames = Object.keys(state.activePeers).sort();
    const otherPeers = peerNames.filter(function (name) {
      return name !== state.username;
    });

    activePeerCount.textContent = String(otherPeers.length);
    activePeersList.innerHTML = "";

    if (otherPeers.length === 0) {
      const emptyLi = document.createElement("li");
      emptyLi.className = "empty-hint";
      emptyLi.textContent = "Chưa có peer nào khác online.";
      activePeersList.appendChild(emptyLi);
      return;
    }

    for (let i = 0; i < otherPeers.length; i += 1) {
      const uname = otherPeers[i];
      const info = state.activePeers[uname];
      const addrKey = info.ip + ":" + info.port;
      const isConnected = Boolean(state.connectedPeers[addrKey]);

      const li = document.createElement("li");
      li.className =
        "nav-item" + (isChannelActive("private", uname) ? " active" : "");
      li.addEventListener("click", function () {
        selectChannel("private", uname);
      });

      const rowInfo = document.createElement("div");
      rowInfo.className = "peer-row-info";

      const rowName = document.createElement("div");
      rowName.className = "peer-row-name";
      const dot = document.createElement("span");
      dot.className = "status-dot online";
      const nameSpan = document.createElement("span");
      nameSpan.textContent = uname;
      rowName.appendChild(dot);
      rowName.appendChild(nameSpan);

      const rowAddr = document.createElement("div");
      rowAddr.className = "peer-row-addr";
      rowAddr.textContent = addrKey;

      rowInfo.appendChild(rowName);
      rowInfo.appendChild(rowAddr);
      li.appendChild(rowInfo);

      const actions = document.createElement("div");
      actions.className = "peer-row-actions";

      const unread = state.unreadCounts.private[uname] || 0;
      if (unread > 0) {
        const badge = document.createElement("span");
        badge.className = "unread-badge";
        badge.textContent = String(unread);
        actions.appendChild(badge);
      }

      const connectBtn = document.createElement("button");
      connectBtn.type = "button";
      connectBtn.className =
        "btn btn-connect" + (isConnected ? " connected" : "");
      connectBtn.textContent = isConnected ? "Connected" : "Connect";
      connectBtn.disabled = isConnected;
      connectBtn.addEventListener("click", function (event) {
        event.stopPropagation();
        connectToPeer(uname, info.ip, info.port, connectBtn);
      });

      actions.appendChild(connectBtn);
      li.appendChild(actions);
      activePeersList.appendChild(li);
    }
  }

  function renderMessages(forceScrollBottom) {
    const nearBottom =
      messagesContainer.scrollHeight -
        messagesContainer.scrollTop -
        messagesContainer.clientHeight <
      60;

    const list =
      state.activeChannel.type === "global"
        ? state.messages.global
        : state.messages.private[state.activeChannel.id] || [];

    messagesContainer.innerHTML = "";

    if (list.length === 0) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "empty-messages";
      emptyDiv.textContent = "Chưa có tin nhắn nào trong kênh này.";
      messagesContainer.appendChild(emptyDiv);
      return;
    }

    for (let i = 0; i < list.length; i += 1) {
      const msg = list[i];
      const isOwn = msg.sender === state.username;

      const item = document.createElement("div");
      item.className = "message-item " + (isOwn ? "own" : "other");

      const meta = document.createElement("div");
      meta.className = "message-meta";

      const senderEl = document.createElement("span");
      senderEl.className = "message-sender";
      senderEl.textContent = isOwn ? msg.sender + " (Bạn)" : msg.sender;

      const timeEl = document.createElement("span");
      timeEl.textContent = formatTimestamp(msg.timestamp);

      meta.appendChild(senderEl);
      meta.appendChild(timeEl);

      const bubble = document.createElement("div");
      bubble.className = "message-bubble";
      if (msg.type === "file") {
        const card = document.createElement("div");
        card.className = "attachment-card";

        const iconEl = document.createElement("span");
        iconEl.className = "attachment-icon";
        iconEl.textContent = "📄";

        const infoEl = document.createElement("div");
        infoEl.className = "attachment-info";

        const nameEl = document.createElement("div");
        nameEl.className = "attachment-name";
        nameEl.textContent = msg.filename || "attachment.bin";

        const metaRow = document.createElement("div");
        metaRow.className = "attachment-meta";

        const sizeSpan = document.createElement("span");
        sizeSpan.textContent = formatFileSize(msg.file_size);
        metaRow.appendChild(sizeSpan);

        if (msg.verified !== false) {
          const verifiedSpan = document.createElement("span");
          verifiedSpan.className = "verified-badge";
          verifiedSpan.textContent = "✔ SHA-256 Verified";
          metaRow.appendChild(verifiedSpan);
        }

        infoEl.appendChild(nameEl);
        infoEl.appendChild(metaRow);

        const dlLink = document.createElement("a");
        dlLink.className = "btn-download";
        dlLink.href =
          msg.download_url ||
          "/download-file/?file_id=" + encodeURIComponent(msg.file_id || "");
        dlLink.setAttribute("download", msg.filename || "file");
        dlLink.textContent = "Tải xuống";

        card.appendChild(iconEl);
        card.appendChild(infoEl);
        card.appendChild(dlLink);
        bubble.appendChild(card);
      } else {
        bubble.textContent = msg.content;
      }

      item.appendChild(meta);
      item.appendChild(bubble);
      messagesContainer.appendChild(item);
    }

    if (forceScrollBottom || nearBottom) {
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
  }

  async function pollTransferStatus() {
    try {
      const response = await fetch("/transfer-status/", {
        credentials: "same-origin",
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      if (data.status !== "success" || !data.transfers) {
        return;
      }
      const entries = Object.values(data.transfers);
      if (entries.length === 0) {
        return;
      }
      entries.sort(function (a, b) {
        return (b.updated_at || 0) - (a.updated_at || 0);
      });
      const latest = entries[0];
      if (!latest || (Date.now() / 1000 - (latest.updated_at || 0)) > 6) {
        return;
      }
      if (latest.status === "completed") {
        updateProgressBar(
          latest.filename,
          100,
          latest.verified ? "100% • Verified SHA-256" : "100%",
          "verified"
        );
        scheduleHideProgressBar(4000);
      } else if (latest.status === "sending" || latest.status === "receiving") {
        updateProgressBar(
          latest.filename,
          latest.percent || 0,
          (latest.percent || 0) + "%",
          ""
        );
      }
    } catch (err) {
      console.warn("Transfer status poll failed:", err);
    }
  }

  async function postJson(url, payload) {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return response.json();
  }

  async function fetchPeers() {
    try {
      const response = await fetch("/get-list/");
      const data = await response.json();
      if (data.status === "success") {
        state.activePeers = normalizePeersPayload(data.peers);
        if (data.connected_peers && typeof data.connected_peers === "object") {
          state.connectedPeers = data.connected_peers;
        }
        renderActivePeers();
        updateComposerState();
      }
    } catch (err) {
      console.error("Failed to fetch peer list:", err);
    }
  }

  async function fetchMessages() {
    try {
      const response = await fetch("/messages/");
      const data = await response.json();
      if (data.status !== "success") {
        return;
      }

      const incomingGlobal = Array.isArray(data.global) ? data.global : [];
      const incomingPrivate =
        data.private && typeof data.private === "object" ? data.private : {};

      let hasActiveChannelUpdate = false;

      // Track unread notifications for global channel
      const prevGlobalCount = state.seenCounts.global || 0;
      if (incomingGlobal.length > prevGlobalCount) {
        const delta = incomingGlobal.length - prevGlobalCount;
        if (state.initialMessagesLoaded) {
          if (!isChannelActive("global", "global") || document.hidden) {
            state.unreadCounts.global =
              (state.unreadCounts.global || 0) + delta;
          }
        }
        if (isChannelActive("global", "global")) {
          hasActiveChannelUpdate = true;
        }
      }
      state.seenCounts.global = incomingGlobal.length;
      state.messages.global = incomingGlobal;

      // Track unread notifications for private 1-1 channels
      const existingKeys = Object.keys(state.messages.private);
      const mergedPrivate = {};
      for (let i = 0; i < existingKeys.length; i += 1) {
        mergedPrivate[existingKeys[i]] = state.messages.private[existingKeys[i]];
      }

      const incomingKeys = Object.keys(incomingPrivate);
      for (let i = 0; i < incomingKeys.length; i += 1) {
        const peerKey = incomingKeys[i];
        const msgs = Array.isArray(incomingPrivate[peerKey])
          ? incomingPrivate[peerKey]
          : [];
        const prevCount = state.seenCounts.private[peerKey] || 0;

        if (msgs.length > prevCount) {
          const delta = msgs.length - prevCount;
          if (state.initialMessagesLoaded) {
            if (!isChannelActive("private", peerKey) || document.hidden) {
              state.unreadCounts.private[peerKey] =
                (state.unreadCounts.private[peerKey] || 0) + delta;
            }
          }
          if (isChannelActive("private", peerKey)) {
            hasActiveChannelUpdate = true;
          }
        }
        state.seenCounts.private[peerKey] = msgs.length;
        mergedPrivate[peerKey] = msgs;
      }
      state.messages.private = mergedPrivate;
      state.initialMessagesLoaded = true;
      if (data.connected_peers && typeof data.connected_peers === "object") {
        state.connectedPeers = data.connected_peers;
      }

      renderChannels();
      renderActivePeers();
      updateComposerState();
      updateTitleBlink();
      if (hasActiveChannelUpdate) {
        renderMessages(false);
      }
      pollTransferStatus();
    } catch (err) {
      console.error("Failed to poll messages:", err);
    }
  }

  async function connectToPeer(username, ip, port, buttonEl) {
    buttonEl.disabled = true;
    buttonEl.textContent = "...";
    try {
      const data = await postJson("/connect-peer/", {
        target_ip: ip,
        target_port: port,
        username: username,
      });

      if (data.status === "success") {
        state.connectedPeers[ip + ":" + port] = {
          username: username,
          ip: ip,
          port: port,
        };
        if (!state.messages.private[username]) {
          state.messages.private[username] = [];
        }
        showToast("Đã kết nối & đồng bộ P2P tới " + username + " (" + ip + ":" + port + ")", false);
        await fetchMessages();
        renderChannels();
        renderActivePeers();
        updateComposerState();
        renderMessages(true);
      } else {
        showToast(data.message || "Không thể kết nối tới peer", true);
        buttonEl.disabled = false;
        buttonEl.textContent = "Connect";
      }
    } catch (err) {
      showToast("Lỗi kết nối tới peer: " + err.message, true);
      buttonEl.disabled = false;
      buttonEl.textContent = "Connect";
    }
  }

  function hasValidSession() {
    const storedUser = sessionStorage.getItem("username");
    const requireCookie = sessionStorage.getItem("require_cookie") === "1";
    const hasCookie = Boolean(
      document.cookie && document.cookie.trim().length > 0
    );
    return Boolean(storedUser) && (!requireCookie || hasCookie);
  }

  function redirectToLogin() {
    sessionStorage.removeItem("username");
    sessionStorage.removeItem("p2p_ip");
    sessionStorage.removeItem("p2p_port");
    sessionStorage.removeItem("require_cookie");
    window.location.replace("/login.html");
  }

  async function enterChatSession(username, p2pIp, p2pPort) {
    state.username = username;
    state.p2pIp = p2pIp || "127.0.0.1";
    state.p2pPort = p2pPort || "--";

    selfAvatar.textContent = state.username.charAt(0).toUpperCase();
    selfUsername.textContent = state.username;
    selfP2pInfo.textContent =
      "P2P: " + state.p2pIp + ":" + state.p2pPort;

    loginOverlay.classList.add("hidden");
    chatApp.classList.remove("hidden");

    await Promise.all([fetchPeers(), fetchMessages()]);
    renderChannels();
    renderMessages(true);
    messageInput.focus();

    if (!state.peersTimerId) {
      state.peersTimerId = setInterval(fetchPeers, PEERS_POLL_MS);
    }
    if (!state.messagesTimerId) {
      state.messagesTimerId = setInterval(fetchMessages, MESSAGES_POLL_MS);
    }
  }

  async function initSession() {
    if (!hasValidSession()) {
      redirectToLogin();
      return;
    }

    let username = sessionStorage.getItem("username");
    let p2pIp = sessionStorage.getItem("p2p_ip") || "127.0.0.1";
    let p2pPort = sessionStorage.getItem("p2p_port") || "--";

    try {
      const resp = await fetch("/peer-info/", { credentials: "same-origin" });
      if (resp.ok) {
        const info = await resp.json();
        if (info.status === "success") {
          if (info.p2p_ip) {
            p2pIp = info.p2p_ip;
            sessionStorage.setItem("p2p_ip", String(p2pIp));
          }
          if (info.p2p_port) {
            p2pPort = info.p2p_port;
            sessionStorage.setItem("p2p_port", String(p2pPort));
          }
          if (info.username) {
            username = info.username;
            sessionStorage.setItem("username", username);
          }
        }
      }
    } catch (err) {
      console.warn("Unable to sync /peer-info/:", err);
    }

    await enterChatSession(username, p2pIp, p2pPort);
  }

  async function handleLoginSubmit(event) {
    event.preventDefault();
    const username = loginUsername.value.trim();
    const password = loginPassword.value;

    loginError.classList.add("hidden");
    if (!username || !password) {
      loginError.textContent = "Vui lòng nhập đầy đủ Username và Password.";
      loginError.classList.remove("hidden");
      return;
    }

    loginSubmitBtn.disabled = true;
    loginSubmitBtn.textContent = "Đang đăng nhập...";

    try {
      const data = await postJson("/login/", {
        username: username,
        password: password,
      });

      if (data.status !== "success") {
        loginError.textContent = data.message || "Đăng nhập thất bại.";
        loginError.classList.remove("hidden");
        return;
      }

      const finalUser = data.username || username;
      sessionStorage.setItem("username", finalUser);
      if (data.p2p_ip) {
        sessionStorage.setItem("p2p_ip", String(data.p2p_ip));
      }
      if (data.p2p_port) {
        sessionStorage.setItem("p2p_port", String(data.p2p_port));
      }

      await enterChatSession(finalUser, data.p2p_ip, data.p2p_port);
    } catch (err) {
      loginError.textContent = "Không thể kết nối tới Peer Node cục bộ.";
      loginError.classList.remove("hidden");
    } finally {
      loginSubmitBtn.disabled = false;
      loginSubmitBtn.textContent = "Đăng nhập";
    }
  }

  async function handleSendMessage(event) {
    event.preventDefault();
    const selectedFile =
      fileInput && fileInput.files && fileInput.files.length > 0
        ? fileInput.files[0]
        : null;
    const content = messageInput.value.trim();

    if (!selectedFile && !content) {
      return;
    }

    sendBtn.disabled = true;
    try {
      if (selectedFile) {
        const isGlobal = state.activeChannel.type === "global";
        const target = isGlobal ? "global" : state.activeChannel.id;
        const endpoint = isGlobal ? null : resolvePeerEndpoint(target);
        if (!isGlobal && !endpoint) {
          showToast("Không tìm thấy địa chỉ IP/Port của " + target, true);
          return;
        }

        updateProgressBar(selectedFile.name, 10, "10% • Đang mã hóa...", "");
        const fileBase64 = await readFileAsBase64(selectedFile);
        updateProgressBar(selectedFile.name, 45, "45% • Đang truyền P2P...", "");

        const filePayload = {
          target: target,
          filename: selectedFile.name,
          file_data_b64: fileBase64,
        };
        if (endpoint) {
          filePayload.target_ip = endpoint.ip;
          filePayload.target_port = endpoint.port;
        }

        const progressTimer = setInterval(pollTransferStatus, 250);
        let fileRes;
        try {
          fileRes = await postJson("/send-file/", filePayload);
        } finally {
          clearInterval(progressTimer);
        }

        if (fileRes.status === "success") {
          updateProgressBar(
            selectedFile.name,
            100,
            "100% • Verified SHA-256",
            "verified"
          );
          scheduleHideProgressBar(4500);
          fileInput.value = "";
          await fetchMessages();
          renderMessages(true);
        } else {
          updateProgressBar(
            selectedFile.name,
            0,
            "Lỗi: " + (fileRes.message || "Thất bại"),
            "error"
          );
          showToast(fileRes.message || "Gửi file thất bại", true);
        }
        return;
      }

      let data;
      if (state.activeChannel.type === "global") {
        data = await postJson("/broadcast-peer/", { content: content });
      } else {
        const peerKey = state.activeChannel.id;
        const endpoint = resolvePeerEndpoint(peerKey);
        if (!endpoint) {
          showToast("Không tìm thấy địa chỉ IP/Port của " + peerKey, true);
          return;
        }
        data = await postJson("/send-peer/", {
          target_ip: endpoint.ip,
          target_port: endpoint.port,
          target_username: peerKey,
          content: content,
        });
      }

      if (data.status === "success") {
        messageInput.value = "";
        await fetchMessages();
        renderMessages(true);
      } else {
        showToast(data.message || "Gửi tin nhắn thất bại", true);
      }
    } catch (err) {
      showToast("Lỗi khi gửi tin nhắn: " + err.message, true);
    } finally {
      sendBtn.disabled = false;
      messageInput.focus();
    }
  }

  window.addEventListener("focus", function () {
    if (state.activeChannel.type === "global") {
      state.unreadCounts.global = 0;
    } else {
      state.unreadCounts.private[state.activeChannel.id] = 0;
    }
    renderChannels();
    renderActivePeers();
    updateTitleBlink();
  });

  async function handleLogout() {
    try {
      await fetch("/logout/", {
        method: "POST",
        credentials: "same-origin",
      });
    } catch (err) {
      console.warn("Logout request failed:", err);
    } finally {
      redirectToLogin();
    }
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", handleLogout);
  }
  loginForm.addEventListener("submit", handleLoginSubmit);
  messageForm.addEventListener("submit", handleSendMessage);

  initSession();
})();
