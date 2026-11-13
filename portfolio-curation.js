/* Public presentation logic only.
 * All project names, dates, work history and descriptions are read exclusively
 * from the portfolio's decrypted HTML after StatiCrypt authentication.
 * This file must never contain portfolio content.
 */
(function () {
  "use strict";

  const VERSION = "20261113-learningfix";
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
    // Prefer the live editor data when available, otherwise read the
    // JSON embedded in the privately decrypted document.
    try {
      if (typeof data !== "undefined" && data && Array.isArray(data.projects)) {
        return data.projects;
      }
    } catch (_err) { /* Optional editor runtime. */ }
    const json = document.getElementById("portfolio-data");
    if (!json) return [];
    try {
      const parsed = JSON.parse(json.textContent);
      return Array.isArray(parsed.projects) ? parsed.projects : [];
    } catch (_err) {
      return [];
    }
  }


  // Only opaque presentation fingerprints are kept in this public script.
  // Names, dates, case content and project evidence stay in encrypted HTML.
  const PROJECT_SECTIONS = [
    {id:"practice",label:"실무·사례"},
    {id:"research",label:"개발·연구"},
    {id:"learning",label:"학습팀"},
    {id:"case",label:"취약점 정리"}
  ];
  const CONTENT_FINGERPRINTS = Object.freeze({
    research: [1451807271,1862098197,3726324113,1000703431],
    case: [3541611610,106018211,3112671157],
    learning: [3651365335,1944395183,3191939619,3348802857,1837791215,2374571855],
    excluded: [1837343204,735539575]
  });
  function contentFingerprint(token) {
    let h = 0x811c9dc5;
    for (let i=0; i<token.length; i++) {
      h = Math.imul(h ^ token.charCodeAt(i), 0x01000193) >>> 0;
    }
    return h >>> 0;
  }
  function titleFingerprints(record) {
    const title = String(record && record.title || "")
      .normalize("NFKC").toLowerCase();
    const parts = title.match(/[a-z0-9가-힣]+/g) || [];
    const tokens = parts.slice();
    // Tolerate space, hyphen, middle dot and underscore variations.
    for (let i=0; i<parts.length-1; i++) tokens.push(parts[i]+parts[i+1]);
    for (let i=0; i<parts.length-2; i++) tokens.push(parts[i]+parts[i+1]+parts[i+2]);
    tokens.push(parts.join(""));
    return Array.from(new Set(tokens.map(contentFingerprint)));
  }
  function projectSection(record) {
    if (!record || typeof record !== "object") return "hidden";
    const hashes = titleFingerprints(record);
    // Never surface the retired verification-environment entry in any tab.
    if (hashes.some(h=>CONTENT_FINGERPRINTS.excluded.includes(h))) return "hidden";
    const explicit = String(record.section || record.group || "").trim().toLowerCase();
    if (["case","vulnerability","vuln","취약점 정리"].includes(explicit)) return "case";
    if (hashes.some(h=>CONTENT_FINGERPRINTS.case.includes(h))) return "case";
    if (["research","development","dev"].includes(explicit)) return "research";
    if (hashes.some(h=>CONTENT_FINGERPRINTS.research.includes(h))) return "research";
    // Only the two explicitly selected education activities are retained.
    if (hashes.some(h=>CONTENT_FINGERPRINTS.learning.includes(h))) return "learning";
    if (["learning","study"].includes(explicit) || record.category==="learning") return "hidden";
    if (explicit==="practice" || explicit==="work") return "practice";
    return "practice";
  }

  function newSectionButton(group, id) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "filter";
    button.dataset.filter = id;
    button.setAttribute("aria-pressed","false");
    button.append(document.createTextNode(group.label));
    const counter = document.createElement("span");
    counter.className = "filter-count";
    counter.id = "count-"+id;
    button.append(counter);
    button.addEventListener("click", () => {
      activeFilter = id;
      renderProjects();
    });
    return button;
  }

  function installSectionFilters() {
    const grid = document.getElementById("project-grid");
    const segments = document.querySelector("#view-projects .segments");
    if (!grid || !segments || typeof renderProjects!=="function" || !sourceProjects().length) return false;
    if (segments.dataset.portfolioSectionsInstalled==="true") return true;
    const practiceButton = segments.querySelector('[data-filter="project"]');
    const learningButton = segments.querySelector('[data-filter="learning"]');
    const allButton = segments.querySelector('[data-filter="all"]');
    if (!allButton || !practiceButton || !learningButton) return false;

    // Keep existing buttons and their native event handlers intact.
    practiceButton.dataset.filter = "practice";
    if (practiceButton.firstChild) practiceButton.firstChild.textContent = "실무·사례";
    const researchButton = newSectionButton(PROJECT_SECTIONS[1], "research");
    const learningTeamButton = newSectionButton(PROJECT_SECTIONS[2], "learning");
    const caseButton = newSectionButton(PROJECT_SECTIONS[3], "case");
    // Remove the original learning button and replace it with one dedicated
    // learning-team button; do not leave two learning controls in the toolbar.
    learningButton.before(researchButton);
    learningButton.before(learningTeamButton);
    learningButton.after(caseButton);
    learningButton.remove();

    const originalRender = renderProjects;
    renderProjects = function() {
      const intended = activeFilter;
      // The original gallery understands only "all", "project" and "learning".
      // Filter/sort into the four sections after it renders the source cards.
      if (intended!=="all") activeFilter="all";
      try { originalRender(); }
      finally { activeFilter=intended; }

      const records = sourceProjects();
      const sections = records.map(projectSection);
      const counts = {
        all: sections.filter(id=>id!=="hidden").length,
        practice: sections.filter(id=>id==="practice").length,
        research: sections.filter(id=>id==="research").length,
        learning: sections.filter(id=>id==="learning").length,
        case: sections.filter(id=>id==="case").length
      };
      const countIds = {
        all:"count-all",practice:"count-project",research:"count-research",
        learning:"count-learning",case:"count-case"
      };
      Object.keys(countIds).forEach(key=>{
        const node = document.getElementById(countIds[key]);
        if (node) node.textContent=String(counts[key]);
      });
      segments.querySelectorAll("[data-filter]").forEach(button=>{
        button.setAttribute("aria-pressed",String(button.dataset.filter===intended));
      });

      const cards = Array.from(grid.querySelectorAll(":scope > .project-card"));
      const matched = PROJECT_SECTIONS.filter(group=>intended==="all"||group.id===intended);
      const headingCount = document.getElementById("result-count");
      if (!cards.length) {
        if (headingCount) headingCount.textContent="검색 결과 0개";
        grid.classList.remove("portfolio-grouped");
        return;
      }
      grid.replaceChildren();
      grid.classList.add("portfolio-grouped");
      let shown=0;
      for (const group of matched) {
        const candidates = cards.filter(card=>{
          const link = card.querySelector('a[href*="#/project/"]');
          const match = link && link.getAttribute("href").match(/#\/project\/(\d+)/);
          const index = match?Number(match[1])-1:-1;
          return index>=0 && sections[index]===group.id;
        });
        if (!candidates.length) continue;
        const section = document.createElement("section");
        section.className="portfolio-section";
        section.dataset.section=group.id;
        const header = document.createElement("header");
        header.className="portfolio-section-heading";
        const name = document.createElement("div");
        name.className="portfolio-section-name";
        const h = document.createElement("h2");
        h.textContent = group.label;
        const count = document.createElement("span");
        count.className="portfolio-section-count";
        count.textContent=String(candidates.length).padStart(2,"0");
        name.append(h,count);
        header.append(name);
        const row = document.createElement("div");
        row.className="portfolio-section-grid";
        candidates.forEach(card=>{
          card.classList.remove("featured");
          const featured = card.querySelector(".featured-label");
          if (featured) featured.remove();
          const kicker = card.querySelector(".card-kicker > span:first-child");
          if (kicker) kicker.textContent=group.label;
          const preview = card.querySelector(".featured-preview");
          if (preview) preview.remove();
          row.append(card);
        });
        section.append(header,row);
        grid.append(section);
        shown+=candidates.length;
      }
      if (!shown) {
        grid.classList.remove("portfolio-grouped");
        const empty = document.createElement("div");
        empty.className="empty-state";
        const title = document.createElement("h2");
        title.textContent = "등록된 항목이 없습니다.";
        const note = document.createElement("p");
        note.textContent = intended==="case"
          ? "잠금 해제한 원본에 등록된 취약점 사례를 확인해 주세요."
          : "다른 분류를 선택하거나 검색어를 변경해 주세요.";
        empty.append(title,note);
        grid.append(empty);
      }
      if (headingCount) {
        const searching = typeof searchQuery!=="undefined" && !!searchQuery.trim();
        headingCount.textContent = (searching?"검색 결과 ":"전체 ")+shown+"개";
      }
    };
    segments.dataset.portfolioSectionsInstalled="true";
    if (!["all","practice","research","learning","case"].includes(activeFilter)) {
      activeFilter="all";
    }
    renderProjects();
    return true;
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
    installSectionFilters();
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
