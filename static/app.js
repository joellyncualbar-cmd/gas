(function () {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  document.querySelectorAll(".toast").forEach((toast, i) => {
    const dismiss = () => {
      toast.classList.add("leaving");
      toast.addEventListener("animationend", () => toast.remove(), { once: true });
    };
    toast.style.setProperty("--d", i * 80 + "ms");
    toast.querySelector(".toast-close")?.addEventListener("click", dismiss);
    setTimeout(dismiss, 5000 + i * 400);
  });

  document.querySelectorAll("[data-count]").forEach((el) => {
    const target = parseInt(el.dataset.count, 10) || 0;
    if (reduceMotion || target === 0) {
      el.textContent = target;
      return;
    }
    const duration = 900;
    const start = performance.now();
    const tick = (now) => {
      const p = Math.min((now - start) / duration, 1);
      el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });

  document.querySelectorAll("[data-toggle-password]").forEach((btn) => {
    const input = document.getElementById(btn.dataset.togglePassword);
    btn.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  document.querySelectorAll("[data-min-today]").forEach((input) => {
    const d = new Date();
    d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
    input.min = d.toISOString().slice(0, 10);
  });

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  document.querySelectorAll("form.form").forEach((form) => {
    form.addEventListener("submit", (e) => {
      if (!form.checkValidity()) {
        e.preventDefault();
        form.querySelectorAll(":invalid").forEach((f) => {
          f.closest(".field")?.classList.add("invalid");
        });
        form.querySelector(":invalid")?.focus();
        return;
      }
      form.querySelector('button[type="submit"]')?.classList.add("loading");
    });
    form.addEventListener("input", (e) => {
      const field = e.target.closest(".field");
      if (field && e.target.checkValidity()) field.classList.remove("invalid");
    });
  });

  document.querySelectorAll("[data-filter-root]").forEach((root) => {
    const table = root.parentElement.querySelector("[data-filter-table]");
    if (!table) return;
    const rows = Array.from(table.querySelectorAll("tbody tr"));
    const emptyMsg = root.parentElement.querySelector(".empty-filter");
    const search = root.querySelector("[data-search]");
    let status = "all";

    const apply = () => {
      const q = search.value.trim().toLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const match = (status === "all" || row.dataset.status === status) && row.textContent.toLowerCase().includes(q);
        row.hidden = !match;
        if (match) visible++;
      });
      if (emptyMsg) emptyMsg.hidden = visible !== 0;
    };

    root.querySelectorAll("[data-status]").forEach((btn) => {
      btn.addEventListener("click", () => {
        root.querySelectorAll("[data-status]").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        status = btn.dataset.status;
        apply();
      });
    });
    search.addEventListener("input", apply);
  });
})();
