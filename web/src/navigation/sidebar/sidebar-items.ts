import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radar,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  Workflow,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "AegisLoop",
    items: [
      { id: "dashboard", title: "Overview", url: "/dashboard", icon: LayoutDashboard },
      {
        id: "offensive",
        title: "Offensive",
        icon: Target,
        subItems: [
          { id: "offensive-overview", title: "Offensive overview", url: "/offensive", icon: LayoutDashboard },
          { id: "tasks", title: "Tasks", url: "/function/tasks", icon: Target },
          { id: "assets", title: "Assets", url: "/function/assets", icon: Network },
          { id: "findings", title: "Findings", url: "/function/findings", icon: Bug },
          { id: "traffic", title: "Traffic", url: "/function/traffic", icon: Activity },
        ],
      },
      {
        id: "defensive",
        title: "Defensive",
        icon: ShieldAlert,
        subItems: [
          { id: "defensive-hunting", title: "Autonomous hunting", url: "/defensive/hunting", icon: Radar },
          { id: "security-sources", title: "Log connections", url: "/function/purple/sources", icon: Plug },
        ],
      },
      {
        id: "closed-loop",
        title: "Closed-loop",
        icon: Workflow,
        subItems: [
          { id: "loop-cycles", title: "Improvement cycles", url: "/closed-loop", icon: Workflow },
          { id: "purple", title: "Attack-defense verification", url: "/function/purple", icon: ShieldCheck },
        ],
      },
    ],
  },
  {
    id: 3,
    label: "Tools",
    items: [
      { id: "chat", title: "Chat", url: "/chat", icon: MessageSquare },
      { id: "commands", title: "Tool executions", url: "/function/commands", icon: Terminal },
      { id: "llm-records", title: "LLM records", url: "/function/llm-records", icon: Radio },
      { id: "sync", title: "Asset synchronization", url: "/function/sync", icon: FolderSync },
      { id: "workspace", title: "Workspace", url: "/function/workspace", icon: FolderOpen },
    ],
  },
  {
    id: 2,
    label: "System",
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
      { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
      { id: "tools", title: "Tools", url: "/system/tools", icon: Wrench },
      { id: "notify", title: "Notifications", url: "/system/notify", icon: BellRing },
      { id: "intercept", title: "Intercept rules", url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", title: "Asset interception", url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", title: "Approvals", url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "logs", title: "Logs", url: "/system/logs", icon: ScrollText },
      { id: "settings", title: "Settings", url: "/system/settings", icon: Settings2 },
    ],
  },
];
