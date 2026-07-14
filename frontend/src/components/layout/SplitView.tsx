import { cn } from "@/lib/utils";

interface SplitViewProps {
  /** Scrollable list pane (left). */
  list: React.ReactNode;
  /** Scrollable detail pane (right). */
  detail: React.ReactNode;
  listClassName?: string;
  className?: string;
}

/**
 * Inbox-style list/detail layout (ADR 0003). Both panes scroll
 * independently; the parent must constrain the height.
 */
export function SplitView({
  list,
  detail,
  listClassName,
  className,
}: SplitViewProps) {
  return (
    <div className={cn("flex h-full min-h-0 overflow-hidden", className)}>
      <aside
        className={cn(
          "w-96 shrink-0 overflow-y-auto border-r border-border",
          listClassName,
        )}
        data-testid="split-view-list"
      >
        {list}
      </aside>
      <section
        className="min-w-0 flex-1 overflow-y-auto"
        data-testid="split-view-detail"
      >
        {detail}
      </section>
    </div>
  );
}
