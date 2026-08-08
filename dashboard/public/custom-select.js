// ── Custom-styled dropdowns (native <select> popups can't be restyled via
// CSS) -- shared by every dashboard page instead of each maintaining its own
// copy, so a fix here (or a future one) doesn't need to be repeated four
// times and inevitably drift out of sync between pages.
function initCustomSelects(root) {
  var selects = root.querySelectorAll("select.form-select:not([data-custom-select-init])");
  Array.prototype.forEach.call(selects, function(select) {
    select.setAttribute("data-custom-select-init", "true");

    var wrapper = document.createElement("div");
    wrapper.className = "custom-select";
    // The native select is hidden once wrapped (.custom-select-native), so
    // its own inline width/flex-shrink (used to size filter dropdowns in a
    // flex header row) would otherwise have nothing left to apply to --
    // carry it onto the wrapper instead.
    if (select.style.width) wrapper.style.width = select.style.width;
    if (select.style.flexShrink) wrapper.style.flexShrink = select.style.flexShrink;
    select.parentNode.insertBefore(wrapper, select);
    wrapper.appendChild(select);
    select.classList.add("custom-select-native");

    var trigger = document.createElement("div");
    trigger.className = "custom-select-trigger";
    trigger.setAttribute("tabindex", "0");
    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    trigger.setAttribute("aria-label", select.getAttribute("aria-label") || "");
    wrapper.appendChild(trigger);

    var listbox = document.createElement("div");
    listbox.className = "custom-select-listbox";
    listbox.setAttribute("role", "listbox");
    listbox.id = select.id + "-listbox";
    trigger.setAttribute("aria-controls", listbox.id);
    wrapper.appendChild(listbox);

    // Single source of truth for open/closed state -- keeps the trigger's
    // aria-expanded in sync with the visible "open" class instead of the
    // half-dozen call sites (click, Escape, option click, outside click,
    // scroll, resize) toggling the class directly and letting the two
    // drift apart. Exposed on the wrapper so the global document/window
    // listeners below -- which only have a wrapper element, not this
    // closure -- can reach it.
    function setOpen(open) {
      wrapper.classList.toggle("open", open);
      trigger.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        // Re-point aria-activedescendant at the current selection each
        // time the listbox opens, since it's explicitly cleared below
        // whenever the listbox closes.
        syncTrigger();
      } else {
        // aria-activedescendant naming an option inside a now-hidden
        // listbox is invalid -- a screen reader has nothing to land on.
        trigger.removeAttribute("aria-activedescendant");
      }
    }
    wrapper._setOpen = setOpen;

    function renderOptions() {
      listbox.innerHTML = "";
      Array.prototype.forEach.call(select.options, function(opt, index) {
        var item = document.createElement("div");
        item.id = listbox.id + "-option-" + index;
        var selected = opt.value === select.value;
        item.className = "custom-select-option" + (selected ? " is-selected" : "");
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", selected ? "true" : "false");
        item.textContent = opt.textContent;
        // Options aren't focusable, so a plain click's mousedown would
        // otherwise blur the trigger and fire the wrapper's focusout
        // handler (below) synchronously -- closing/hiding the listbox
        // before the click itself fires, which then gets silently
        // suppressed by the browser since its target just went
        // display:none mid-gesture. preventDefault() here keeps focus on
        // the trigger throughout the click, so this never races.
        item.addEventListener("mousedown", function(evt) {
          evt.preventDefault();
        });
        item.addEventListener("click", function() {
          if (select.disabled) return;
          if (select.value !== opt.value) {
            select.value = opt.value;
            select.dispatchEvent(new Event("change", { bubbles: true }));
          }
          syncTrigger();
          setOpen(false);
        });
        listbox.appendChild(item);
      });
    }

    function syncTrigger() {
      var current = select.options[select.selectedIndex];
      trigger.textContent = current ? current.textContent : "";
      // Cleared unconditionally first so a selectedIndex of -1 (nothing
      // selected) or an empty options list leaves no stale reference to a
      // now-nonexistent option, instead of the last one ever set lingering
      // forever.
      trigger.removeAttribute("aria-activedescendant");
      Array.prototype.forEach.call(listbox.children, function(item, i) {
        var selected = i === select.selectedIndex;
        item.classList.toggle("is-selected", selected);
        item.setAttribute("aria-selected", selected ? "true" : "false");
        if (selected) trigger.setAttribute("aria-activedescendant", item.id);
      });
    }

    // The native select's own disabled state has no visual/interactive
    // equivalent on the trigger <div> that replaces it -- without this, a
    // disabled select would render as a fully clickable, focusable
    // dropdown, silently losing the "you can't touch this" semantics an
    // analyst relies on from a real disabled control.
    function syncDisabled() {
      var disabled = select.disabled;
      trigger.setAttribute("aria-disabled", disabled ? "true" : "false");
      trigger.setAttribute("tabindex", disabled ? "-1" : "0");
      // A caller can disable the select while its listbox is already open
      // (eg. disabling a filter mid-interaction) -- leaving it open would
      // still let a click on an option commit a value change on a control
      // that's supposed to be inert, so force it closed too.
      if (disabled && wrapper.classList.contains("open")) {
        setOpen(false);
      }
    }

    // Callers that mutate the underlying select after init (new/removed
    // <option>s, a value set programmatically, disabling it) call this to
    // resync the overlay instead of it silently going stale.
    select._refreshCustomSelect = function() {
      renderOptions();
      syncTrigger();
      syncDisabled();
    };

    // Shared by the click and ArrowUp/ArrowDown paths so keyboard-only
    // opening (no prior click) -- or reopening after a scroll/resize
    // shifted the trigger since the last open -- always positions the
    // listbox against the trigger's current rect instead of an unset or
    // stale one.
    function positionAndOpen() {
      var rect = trigger.getBoundingClientRect();
      listbox.style.left = rect.left + "px";
      listbox.style.top = (rect.bottom + 4) + "px";
      listbox.style.width = rect.width + "px";
      setOpen(true);
    }

    trigger.addEventListener("click", function() {
      if (select.disabled) return;
      if (wrapper.classList.contains("open")) {
        setOpen(false);
        return;
      }
      positionAndOpen();
    });

    trigger.addEventListener("keydown", function(evt) {
      if (select.disabled) return;
      if (evt.key === "Enter" || evt.key === " ") {
        evt.preventDefault();
        trigger.click();
      } else if (evt.key === "ArrowDown" || evt.key === "ArrowUp") {
        evt.preventDefault();
        var wasOpen = wrapper.classList.contains("open");
        positionAndOpen();
        // The first Arrow press while closed only opens the listbox at the
        // current selection -- it doesn't also move the value in the same
        // keystroke, matching a plain click (which opens without
        // selecting) rather than silently committing a change the analyst
        // never explicitly picked.
        if (!wasOpen) return;
        var items = Array.prototype.slice.call(listbox.children);
        var idx = items.findIndex(function(i) { return i.classList.contains("is-selected"); });
        var nextIdx = evt.key === "ArrowDown" ? Math.min(idx + 1, items.length - 1) : Math.max(idx - 1, 0);
        if (nextIdx !== idx) {
          select.selectedIndex = nextIdx;
          select.dispatchEvent(new Event("change", { bubbles: true }));
        }
        syncTrigger();
      } else if (evt.key === "Escape") {
        setOpen(false);
      }
    });

    wrapper.addEventListener("focusout", function(evt) {
      if (!wrapper.contains(evt.relatedTarget)) {
        setOpen(false);
      }
    });

    renderOptions();
    syncTrigger();
    syncDisabled();
  });
}

document.addEventListener("click", function(evt) {
  Array.prototype.forEach.call(document.querySelectorAll(".custom-select.open"), function(w) {
    if (!w.contains(evt.target) && w._setOpen) w._setOpen(false);
  });
});

document.addEventListener("keydown", function(evt) {
  if (evt.key === "Escape") {
    Array.prototype.forEach.call(document.querySelectorAll(".custom-select.open"), function(w) {
      if (w._setOpen) w._setOpen(false);
    });
  }
});

window.addEventListener("scroll", function(evt) {
  if (
    evt.target instanceof Element &&
    evt.target.closest(".custom-select-listbox")
  ) {
    return;
  }
  Array.prototype.forEach.call(document.querySelectorAll(".custom-select.open"), function(w) {
    if (w._setOpen) w._setOpen(false);
  });
}, true);

window.addEventListener("resize", function() {
  Array.prototype.forEach.call(document.querySelectorAll(".custom-select.open"), function(w) {
    if (w._setOpen) w._setOpen(false);
  });
});
