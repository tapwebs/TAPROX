import { NAV_ITEMS, NAV_PARENT, type RouteId } from "@/app/routes";

const ITEM_BASE =
  "group relative flex h-9 items-center gap-3 rounded-md px-3 text-sm font-medium transition-all duration-150";

export function Sidebar({ current }: { current: RouteId }) {
  return (
    <aside className="sticky top-0 z-20 flex h-dvh flex-col overflow-y-auto border-r border-white/[0.07] bg-[rgba(20,20,24,0.78)] backdrop-blur-[14px] backdrop-saturate-[130%]">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-white/[0.07] px-4">
        <div className="flex items-center gap-2.5">
          <img src="/favicon.svg" alt="" className="size-6 shrink-0 drop-shadow-[0_0_8px_rgba(229,32,58,0.4)]" />
          <span className="hidden text-sm font-bold tracking-wider text-fg lg:inline">TAPROX</span>
        </div>
        <span className="hidden rounded border border-line bg-inset px-1.5 py-0.5 font-mono text-[10px] font-semibold text-accent lg:inline">
          PRO
        </span>
      </div>
      <nav aria-label="Primary" className="flex-1 p-2.5">
        <ul className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const label = <span className="sr-only lg:not-sr-only lg:flex-1 lg:truncate">{item.label}</span>;
            if (item.route) {
              const active = item.route === (NAV_PARENT[current] ?? current);
              return (
                <li key={item.label}>
                  <a
                    href={`#/${item.route}`}
                    aria-current={active ? "page" : undefined}
                    title={item.label}
                    className={`${ITEM_BASE} cursor-pointer ${
                      active
                        ? "bg-accent/[0.12] text-fg shadow-[inset_3px_0_0_var(--color-accent)] ring-1 ring-accent/20"
                        : "text-fg-muted hover:bg-white/[0.04] hover:text-fg"
                    }`}
                  >
                    <Icon
                      aria-hidden="true"
                      className={`size-4 shrink-0 transition-colors ${
                        active ? "text-accent" : "text-fg-subtle group-hover:text-fg"
                      }`}
                    />
                    {label}
                  </a>
                </li>
              );
            }
            return (
              <li key={item.label}>
                <span
                  aria-disabled="true"
                  title={`${item.label}: planned for phase ${String(item.phase)}`}
                  className={`${ITEM_BASE} cursor-not-allowed text-fg-subtle opacity-60`}
                >
                  <Icon aria-hidden="true" className="size-4 shrink-0 text-fg-subtle" />
                  {label}
                  <span className="sr-only">(planned)</span>
                  <span className="hidden shrink-0 rounded border border-line bg-inset/50 px-1 font-mono text-[10px] leading-4 text-fg-subtle lg:inline">
                    P{item.phase}
                  </span>
                </span>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="border-t border-white/[0.07] p-3">
        <div className="hidden items-center justify-between font-mono text-[11px] text-fg-subtle lg:flex">
          <span>OPERATIONS</span>
          <span className="flex items-center gap-1.5 text-success">
            <span className="size-1.5 rounded-full bg-success animate-pulse" /> ONLINE
          </span>
        </div>
      </div>
    </aside>
  );
}
