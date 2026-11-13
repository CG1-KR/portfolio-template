/* Public presentation logic only.
 * All project names, dates, work history and descriptions are read exclusively
 * from the portfolio's decrypted HTML after StatiCrypt authentication.
 * This file must never contain portfolio content.
 */
(function () {
  "use strict";

  const VERSION = "20261113-research-order2";
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
  // Vulnerability case notes have a dedicated top-level page.
  const PROJECT_SECTIONS = [
    {id:"practice",label:"실무·사례"},
    {id:"research",label:"개발·연구"},
    {id:"learning",label:"학습"}
  ];
  const CONTENT_FINGERPRINTS = Object.freeze({
    research: [1451807271,1862098197,3726324113,1000703431],
    case: [3541611610,106018211,3112671157],
    learning: [3651365335,1944395183,2263963833,3391912787,2465745729,1818730770,3191939619,3348802857,1837791215,2374571855],
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

  // The four permitted development entries are ranked by their existing
  // public fingerprints. Actual titles and portfolio content stay encrypted.
  // Sorting changes only gallery presentation, never project indices or links.
  function researchDisplayRank(record) {
    if (!record) return CONTENT_FINGERPRINTS.research.length;
    const hashes = titleFingerprints(record);
    const index = CONTENT_FINGERPRINTS.research.findIndex(hash => hashes.includes(hash));
    return index < 0 ? CONTENT_FINGERPRINTS.research.length : index;
  }

  function researchCardRank(card, records) {
    // Rank by the actual visible card heading first. A decrypted portfolio may
    // load a browser-local edited model whose indices differ from embedded JSON.
    // Reading the card avoids assigning ranks to the wrong project.
    const title = card && card.querySelector("h2, .project-title, h3");
    if (title && title.textContent.trim()) {
      const rank = researchDisplayRank({title:title.textContent.trim()});
      if (rank < CONTENT_FINGERPRINTS.research.length) return rank;
    }
    const link = card && card.querySelector('a[href*="#/project/"]');
    const match = link && link.getAttribute("href") &&
      link.getAttribute("href").match(/#\/project\/(\d+)/);
    const index = match ? Number(match[1]) - 1 : -1;
    return index >= 0 && index < records.length
      ? researchDisplayRank(records[index])
      : CONTENT_FINGERPRINTS.research.length;
  }

  // Re-establish visual order when the original portfolio re-renders cards
  // on search, filter changes, edits or browser-local draft restoration.
  function synchronizeResearchDisplayOrder() {
    const grid = document.getElementById("project-grid");
    if (!grid) return false;
    const sections = grid.querySelectorAll(
      '.portfolio-section[data-section="research"] .portfolio-section-grid'
    );
    let changed = false;
    for (const row of sections) {
      const before = Array.from(row.querySelectorAll(":scope > .project-card"));
      if (before.length < 2) continue;
      const after = before.slice().sort((a,b)=>
        researchCardRank(a,[])-researchCardRank(b,[])
      );
      if (after.some((card,i)=>card!==before[i])) {
        row.append(...after);
        changed = true;
      }
    }
    return changed;
  }

  // Restore a missing education card from an existing *decrypted* career
  // record. We never publish this course's name, date or summary in JavaScript.
  // If it is absent from both projects and career records, do not invent data.
  function restoreMissingLearningFromCareer() {
    let model;
    try {
      model = typeof data !== "undefined" && data && Array.isArray(data.projects)
        ? data : null;
    } catch (_err) { model = null; }
    if (!model) return false;

    const courseTokens = CONTENT_FINGERPRINTS.learning.slice(0,6);
    const mentionsCourse = value => {
      const text = typeof value === "string" ? value : "";
      return titleFingerprints({ title:text }).some(hash => courseTokens.includes(hash));
    };
    if (model.projects.some(p => mentionsCourse(p.title))) return false;

    const activities = [];
    for (const field of ["experience","education","activities","certifications"]) {
      if (Array.isArray(model[field])) {
        activities.push(...model[field].filter(x => x && typeof x === "object"));
      }
    }
    // The original site's experience timeline often holds the course, even
    // when the gallery's projects array does not.
    const found = activities.find(e =>
      [e.title,e.name,e.description,e.organization,e.period]
        .some(mentionsCourse)
    );
    if (!found) return false;

    const description = String(found.description || found.summary || "").trim();
    const heading = String(found.title || found.name || "").trim();
    // Prefer the actual title of the course. When the timeline's title is a
    // broad grouping, extract only the matching segment of its own text.
    const segments = [heading,...description.split(/[;\n|]/)]
      .map(x => x.trim()).filter(Boolean);
    const coursePart = segments.find(mentionsCourse);
    if (!coursePart) return false;

    let courseTitle = mentionsCourse(heading) ? heading : coursePart;
    courseTitle = courseTitle.replace(/^\s*20\d{2}[.\-/]\d{1,2}\s*[:·\-–]?\s*/, "").trim();
    if (courseTitle.length > 120) courseTitle = courseTitle.slice(0,120).trim();

    const periodFromSource = String(found.period || found.date || "").trim();
    const dateMatch = coursePart.match(/20\d{2}[.\-/]\d{1,2}/);
    // A broad career timeline can mention the course without having the
    // course's dates or organization; do not copy those unrelated values.
    const ownTitle = mentionsCourse(heading);
    const period = ownTitle ? (periodFromSource || (dateMatch ? dateMatch[0] : "")) :
      (dateMatch ? dateMatch[0] : "");
    const context = ownTitle ? (description || coursePart) : coursePart;
    const organization = ownTitle ? String(found.organization || "").trim() : "";
    const record = {
      title:courseTitle,
      category:"learning",
      section:"learning",
      period:period,
      role:organization,
      summary:context,
      problem:context,
      approach:context,
      outcome:"",
      tags:[],
      url:""
    };
    // Insert before the first already-known learning item, preserving the
    // other entries and the numeric detail routes used by the original app.
    const at = model.projects.findIndex(p => projectSection(p)==="learning");
    model.projects.splice(at < 0 ? model.projects.length : at,0,record);
    if (typeof renderProjects==="function") renderProjects();
    return true;
  }

  // Legacy encrypted templates can regenerate their own labels after startup.
  // Normalize only the learning filter/section presentation; leave project
  // titles, evidence, details, and the encrypted source untouched.
  function normalizeLearningLabels() {
    const host = document.getElementById("view-projects");
    if (!host) return;
    const stale = /^학습[\s·ㆍ.-]*팀$/u;
    const filter = host.querySelector(".segments [data-filter='learning']");
    if (filter) {
      // Keep count spans, click handlers and accessibility properties intact.
      const first = filter.firstChild;
      if (first && first.nodeType === 3 && stale.test(first.textContent.trim())) {
        first.textContent = "학습";
      } else if (first && first.nodeType === 1 && stale.test(first.textContent.trim())) {
        first.textContent = "학습";
      }
    }
    const titleSelectors = [
      ".portfolio-section[data-section='learning'] .portfolio-section-name h2",
      ".portfolio-section[data-section='learning'] .card-kicker > span:first-child"
    ];
    for (const selector of titleSelectors) {
      host.querySelectorAll(selector).forEach(node => {
        if (stale.test(node.textContent.trim())) node.textContent = "학습";
      });
    }
  }

  function watchLearningLabels() {
    const host = document.getElementById("view-projects");
    if (!host || host.dataset.learningLabelWatcher === "1") return;
    host.dataset.learningLabelWatcher = "1";
    normalizeLearningLabels();
    // Other legacy renderers may replace the filter buttons or section
    // headings asynchronously; correct those mutations without retry loops.
    const observer = new MutationObserver(() => {
      normalizeLearningLabels();
      synchronizeResearchDisplayOrder();
    });
    observer.observe(host, {childList:true,characterData:true,subtree:true});
    synchronizeResearchDisplayOrder();
  }

  // Build one canonical toolbar. The encrypted portfolio may already include
  // project/research/learning-team controls with different data-filter names.
  // Appending extra controls to those produces duplicate visible tabs.
  // Replace the entire control set instead of guessing which old button to drop.
  function newSectionButton(group) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "filter";
    button.dataset.filter = group.id;
    button.setAttribute("aria-pressed", "false");
    button.append(document.createTextNode(group.label));
    const counter = document.createElement("span");
    counter.className = "filter-count";
    counter.id = {
      all:"count-all", practice:"count-project", research:"count-research",
      learning:"count-learning", case:"count-case"
    }[group.id];
    button.append(counter);
    button.addEventListener("click", event => {
      // Do not allow legacy delegated filter handlers to react to our buttons.
      if (event && typeof event.stopPropagation === "function") event.stopPropagation();
      activeFilter = group.id;
      renderProjects();
    });
    return button;
  }

  function installSectionFilters() {
    const grid = document.getElementById("project-grid");
    const segments = document.querySelector("#view-projects .segments");
    if (!grid || !segments || typeof renderProjects!=="function" || !sourceProjects().length) return false;
    if (segments.dataset.portfolioSectionsInstalled==="true") return true;

    const intendedFilters = [{id:"all",label:"전체"}].concat(PROJECT_SECTIONS);
    const buttons = intendedFilters.map(newSectionButton);
    // Preserve unknown legacy count targets invisibly if the original renderer
    // updates them. They are no longer independently clickable filters.
    const reservedIds = new Set(buttons.map(b => b.querySelector(".filter-count").id));
    const legacyIds = Array.from(segments.querySelectorAll("[id]"))
      .map(node => node.id)
      .filter(id => id && !reservedIds.has(id) && /^count[-_]/.test(id));
    const compatibility = document.createElement("span");
    compatibility.hidden = true;
    compatibility.setAttribute("aria-hidden", "true");
    for (const id of new Set(legacyIds)) {
      const node = document.createElement("span");
      node.id = id;
      compatibility.append(node);
    }
    segments.replaceChildren(...buttons, compatibility);

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
        all: sections.filter(id=>id!=="hidden" && id!=="case").length,
        practice: sections.filter(id=>id==="practice").length,
        research: sections.filter(id=>id==="research").length,
        learning: sections.filter(id=>id==="learning").length
      };
      const countIds = {
        all:"count-all",practice:"count-project",research:"count-research",
        learning:"count-learning"
      };
      Object.keys(countIds).forEach(key=>{
        const node = document.getElementById(countIds[key]);
        if (node) node.textContent=String(counts[key]);
      });
      const sideCount = document.getElementById("nav-project-count");
      if (sideCount) sideCount.textContent=String(counts.all).padStart(2,"0");
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
        if (group.id==="research") {
          candidates.sort((a,b)=>researchCardRank(a,records)-researchCardRank(b,records));
        }
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
        note.textContent = "다른 분류를 선택하거나 검색어를 변경해 주세요.";
        empty.append(title,note);
        grid.append(empty);
      }
      if (headingCount) {
        const searching = typeof searchQuery!=="undefined" && !!searchQuery.trim();
        headingCount.textContent = (searching?"검색 결과 ":"전체 ")+shown+"개";
      }
      normalizeLearningLabels();
      synchronizeResearchDisplayOrder();
    };
    segments.dataset.portfolioSectionsInstalled="true";
    if (!["all","practice","research","learning"].includes(activeFilter)) {
      activeFilter="all";
    }
    renderProjects();
    return true;
  }


  // CASES: only the *presentation* is public. Entries are read exclusively
  // from the site's private, decrypted JSON after a successful unlock.
  const CASES_ROUTE="#/cases";
  function caseNavLink(mobile) {
    const a=document.createElement("a");
    a.href=CASES_ROUTE;
    if (!mobile) a.className="nav-link";
    a.dataset.nav="cases";
    const icon=document.createElementNS("http://www.w3.org/2000/svg","svg");
    icon.setAttribute("viewBox","0 0 24 24");
    icon.setAttribute("fill","none");
    icon.setAttribute("stroke","currentColor");
    icon.setAttribute("stroke-width","1.6");
    icon.setAttribute("aria-hidden","true");
    icon.setAttribute("stroke-linecap","round");
    icon.setAttribute("stroke-linejoin","round");
    const shape=document.createElementNS("http://www.w3.org/2000/svg","path");
    shape.setAttribute("d","M12 2 20 5v6c0 5-3.1 8.2-8 11-4.9-2.8-8-6-8-11V5l8-3Z");
    const check=document.createElementNS("http://www.w3.org/2000/svg","path");
    check.setAttribute("d","m9 12 2 2 4-4");
    icon.append(shape,check);
    const label=document.createElement("span");
    label.textContent="취약점 정리";
    a.append(icon,label);
    return a;
  }
  function installCaseNavigation() {
    for(const [nav,mobile] of [
      [document.querySelector(".app-nav"),false],
      [document.querySelector(".bottom-nav"),true]
    ]) {
      if(!nav||nav.querySelector('[data-nav="cases"]'))continue;
      const a=caseNavLink(mobile);
      const before=nav.querySelector('[data-nav="projects"]');
      if(before)before.after(a);else nav.append(a);
    }
  }
  function installCasesPage() {
    let view=document.getElementById("view-cases");
    if(view)return view;
    const workspace=document.getElementById("workspace");
    if(!workspace)return null;
    view=document.createElement("section");
    view.id="view-cases";
    view.className="view portfolio-cases-view";
    view.dataset.view="cases";
    view.hidden=true;
    view.setAttribute("aria-labelledby","cases-title");
    const title=document.createElement("div");
    title.className="view-title";
    const h=document.createElement("h1");
    h.id="cases-title";
    h.textContent="취약점 정리";
    h.tabIndex=-1;
    title.append(h);
    const list=document.createElement("div");
    list.id="case-list";
    list.className="portfolio-case-list";
    list.setAttribute("role","list");
    view.append(title,list);
    const projects=document.getElementById("view-projects");
    if(projects)projects.after(view);else workspace.append(view);
    return view;
  }
  function renderCasesPage() {
    const host=document.getElementById("case-list");
    if(!host)return 0;
    host.replaceChildren();
    let count=0;
    sourceProjects().forEach((p,index)=>{
      if(projectSection(p)!=="case")return;
      const row=document.createElement("article");
      row.className="portfolio-case-row";
      row.setAttribute("role","listitem");
      const h=document.createElement("h2");
      h.className="portfolio-case-name";
      h.textContent=String(p.title||"제목 없음");
      const summary=document.createElement("p");
      summary.className="portfolio-case-summary";
      const overview=String(p.summary||p.problem||"").replace(/\s+/g," ").trim();
      summary.textContent=overview.length>170?overview.slice(0,170).trimEnd()+"…":overview;
      const detail=document.createElement("a");
      detail.className="portfolio-case-open";
      detail.href="#/project/"+(index+1);
      detail.setAttribute("aria-label",h.textContent+" 상세 보기");
      detail.append(document.createTextNode("상세 보기"));
      const arrow=document.createElement("span");
      arrow.setAttribute("aria-hidden","true");
      arrow.textContent="→";
      detail.append(arrow);
      row.append(h,summary,detail);
      host.append(row);
      count++;
    });
    if(!count){
      const empty=document.createElement("p");
      empty.className="portfolio-cases-empty";
      empty.textContent="등록된 취약점 사례가 없습니다.";
      host.append(empty);
    }
    return count;
  }
  function caseRouteDetail() {
    const m=location.hash.match(/^#\/project\/(\d+)$/);
    const records=sourceProjects();
    const index=m?Number(m[1])-1:-1;
    return index>=0&&index<records.length&&projectSection(records[index])==="case";
  }
  function fixCaseDetailNavigation() {
    const root=document.getElementById("view-detail");
    if(!root)return;
    if(!caseRouteDetail()){
      root.classList.remove("portfolio-case-detail");
      return;
    }
    root.classList.add("portfolio-case-detail");
    const back=root.querySelector(".back-link");
    if(back){
      back.href=CASES_ROUTE;
      const textNode=Array.from(back.childNodes).find(n=>n.nodeType===3&&n.textContent.trim());
      if(textNode)textNode.textContent="취약점 정리로 돌아가기";
      else back.append(document.createTextNode("취약점 정리로 돌아가기"));
    }
    const category=root.querySelector(".detail-category > span:first-child");
    if(category)category.textContent="취약점 정리";
    document.querySelectorAll('[data-nav="projects"]').forEach(n=>n.removeAttribute("aria-current"));
    document.querySelectorAll('[data-nav="cases"]').forEach(n=>n.setAttribute("aria-current","page"));
  }
  function installCasesRoute() {
    if(typeof route!=="function"||typeof renderRoute!=="function")return false;
    if(route.__portfolioCasesRoute===true)return true;
    const previousRoute=route;
    route=function(){
      if(location.hash===CASES_ROUTE)return {view:"cases"};
      return previousRoute();
    };
    route.__portfolioCasesRoute=true;
    const previousRender=renderRoute;
    renderRoute=function(focus){
      previousRender(focus);
      if(location.hash===CASES_ROUTE){
        renderCasesPage();
        const crumb=document.getElementById("current-screen");
        if(crumb)crumb.textContent="취약점 정리";
        document.title="취약점 정리 · Portfolio";
      }else{
        fixCaseDetailNavigation();
      }
    };
    renderRoute(false);
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
    restoreMissingLearningFromCareer();
    installSectionFilters();
    watchLearningLabels();
    installCaseNavigation();
    installCasesPage();
    installCasesRoute();
    renderOnePageDetail();
    fixCaseDetailNavigation();
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
