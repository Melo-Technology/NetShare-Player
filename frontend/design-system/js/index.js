import { defineAppShell } from "./components/app-shell.js";
import { defineSidebar } from "./components/sidebar.js";
import { defineHeader } from "./components/header.js";
import { defineCard } from "./components/card.js";
import { defineMetricCard } from "./components/metric-card.js";
import { defineStatusBadge } from "./components/status-badge.js";
import { defineDialog } from "./components/dialog.js";
import { defineToast } from "./components/toast.js";
import { defineStates } from "./components/states.js";
import { defineSettingsComponents } from "./components/settings.js";

export function defineNetShareDesignSystem() {
  defineAppShell();
  defineSidebar();
  defineHeader();
  defineCard();
  defineMetricCard();
  defineStatusBadge();
  defineDialog();
  defineToast();
  defineStates();
  defineSettingsComponents();
}

defineNetShareDesignSystem();
