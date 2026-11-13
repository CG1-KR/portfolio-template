/* Public presentation logic only.
 * All project names, dates, work history and descriptions are read exclusively
 * from the portfolio's decrypted HTML after StatiCrypt authentication.
 * This file must never contain portfolio content.
 */
(function () {
  "use strict";

  const VERSION = "20261113-privacy";
  const LABELS = [
    { key: "problem", label: "개요 및 역할" },
    { key: "approach", label: "프로젝트 내용" },
    { key: "outcome", label: "결과 및 성과" }
  ];

  function preparePlaintext(plaintext) {
    if (typeof plaintext !== "string" || !/<\/body\s*>/i.test(plaintext)) return plaintext;
    let html = plaintext;
    if (!html.includes("portfolio-sections.css")) {
      html = html.replace(/<\/head\s*>/i,
        '<link rel="stylesheet" href="./portfolio-sections.css?v=' + VERSION + '"></head>');
    }
    if (!html.includes("data-portfolio-enhance")) {
      html = html.replace(/<\/body\s*>/i,
        '<script src="./portfolio-curation.js?v=' + VERSION +
        '" data-portfolio-enhance="true"></script></body>');
    }
    return html;
  }

  function eliminateRedundancies() {
    const selectors = [
      "#view-profile > .view-title .view-subtitle",
      "#view-projects > .view-title .view-subtitle",
      "#view-profile-details > .view-title .view-subtitle",
      "#view-contact > .view-title .view-subtitle",
      "#view-projects > .view-title .view-state",
      "#view-projects .result-bar > span:not(#result-count)",
      "#view-projects .list-note",
      ".app-sidebar .nav-caption",
      ".app-sidebar .sidebar-note",
      ".app-brand small",
      ".portfolio-section-heading > p",
      ".portfolio-detail-section-heading .portfolio-detail-caption",
      "#view-detail .detail-heading .view-subtitle",
      "#view-detail .detail-meta .related-link"
    ];
    for (const selector of selectors) {
      document.querySelectorAll(selector).forEach(el => el.remove());
    }
  }

  function sourceProjects() {
    const json = document.getElementById("portfolio-data");
    if (!json) return [];
    try {
      const parsed = JSON.parse(json.textContent);
      return Array.isArray(parsed.projects) ? parsed.projects : [];
    } catch (_err) {
      return [];
    }
  }

  function renderParagraphs(container, text) {
    const body = typeof text === "string" ? text.trim() : "";
    if (!body) return;
    for (const block of body.split(/\n[ \t]*\n+/)) {
      if (!block.trim()) continue;
      const label = block.match(/^\[([^\]\n]{1,100})\]\s*\n([\s\S]*)$/);
      if (label) {
        const h = document.createElement("h3");
        h.className = "portfolio-detail-subheading";
        h.textContent = label[1];
        container.append(h);
        if (!label[2].trim()) continue;
      }
      const p = document.createElement("p");
      p.textContent = label ? label[2].trim() : block.trim();
      container.append(p);
    }
  }

  function renderOnePageDetail() {
    const root = document.getElementById("view-detail");
    if (!root || root.querySelector(".portfolio-detail-document")) return;
    const main = root.querySelector(".detail-main");
    if (!main || !main.querySelector(".detail-tabs,[role='tablist']")) return;
    const match = location.hash.match(/^#\/project\/(\d+)$/);
    if (!match) return;
    const projects = sourceProjects();
    const record = projects[Number(match[1]) - 1];
    if (!record) return;

    const wrapper = document.createElement("div");
    wrapper.className = "portfolio-detail-document";
    for (let i = 0; i < LABELS.length; i++) {
      const entry = LABELS[i];
      const card = document.createElement("section");
      card.className = "portfolio-detail-section portfolio-detail-" + entry.key;
      const header = document.createElement("div");
      header.className = "portfolio-detail-section-heading";
      const number = document.createElement("span");
      number.className = "portfolio-detail-number";
      number.textContent = String(i + 1).padStart(2, "0");
      const h = document.createElement("h2");
      h.textContent = entry.label;
      header.append(number, h);
      const body = document.createElement("div");
      body.className = "portfolio-detail-body";

      if (entry.key === "problem" && typeof record.role === "string" && record.role.trim()) {
        const roleBox = document.createElement("div");
        roleBox.className = "portfolio-role-overview";
        const roleRow = document.createElement("div");
        roleRow.className = "portfolio-role-row";
        const label = document.createElement("span");
        label.className = "portfolio-role-label";
        label.textContent = "담당 역할";
        const roleText = document.createElement("strong");
        roleText.className = "portfolio-role-value";
        roleText.textContent = record.role;
        roleRow.append(label, roleText);
        roleBox.append(roleRow);
        body.append(roleBox);
      }
      renderParagraphs(body, record[entry.key]);
      card.append(header, body);
      wrapper.append(card);
    }
    main.replaceChildren(wrapper);
    main.classList.add("portfolio-detail-main");
    root.classList.add("portfolio-detail-view");
    eliminateRedundancies();
  }

  function enableUnlockedView() {
    if (!document.body || document.body.dataset.neumorphism !== "portfolio") return;
    eliminateRedundancies();
    renderOnePageDetail();
    const detailRoot = document.getElementById("view-detail");
    if (detailRoot) {
      const observer = new MutationObserver(() => {
        if (detailRoot.querySelector(".detail-tabs,[role='tablist']")) {
          renderOnePageDetail();
        } else {
          eliminateRedundancies();
        }
      });
      observer.observe(detailRoot, { childList: true });
    }
  }

  // This is available on the password page but only receives private HTML
  // after StatiCrypt has authenticated and decrypted it in the browser.
  window.PortfolioCuration = { preparePlaintext };

  if (document.currentScript &&
      document.currentScript.dataset.portfolioEnhance === "true") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", enableUnlockedView, {once:true});
    } else {
      enableUnlockedView();
    }
  }
})();
