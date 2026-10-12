import { LayoutDashboard, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

type PageHeaderProps = {
    eyebrow: ReactNode;
    title: ReactNode;
    icon?: LucideIcon;
    actions?: ReactNode;
    titleId?: string;
    children?: ReactNode;
};

/** Shared page identity and actions; tables and form controls stay in page content. */
export default function PageHeader({ eyebrow, title, icon: Icon = LayoutDashboard, actions, titleId, children }: PageHeaderProps) {
    return (
        <header data-page-header className="w-full min-w-0 shrink-0 rounded-2xl border border-slate-200/90 dark:border-slate-700/80 bg-gradient-to-br from-slate-50 via-white to-cyan-50/50 dark:from-slate-900/85 dark:via-slate-900/60 dark:to-cyan-950/25 px-6 py-8 sm:px-10 sm:py-10 shadow-sm">
            <div className="flex min-w-0 flex-col gap-6 xl:flex-row xl:items-center xl:justify-between">
                <div className="flex min-w-0 flex-1 items-stretch gap-5">
                    <div className="flex w-14 shrink-0 items-center justify-center self-stretch rounded-xl border border-cyan-500/30 bg-cyan-500/10 py-3 text-cyan-700 dark:text-cyan-300">
                        <Icon className="h-7 w-7" aria-hidden="true" />
                    </div>
                    <div className="min-w-0 flex-1 space-y-3">
                        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 [overflow-wrap:anywhere]">{eyebrow}</div>
                        <h1 id={titleId} className="text-2xl sm:text-[1.75rem] font-bold tracking-tight text-slate-900 dark:text-white [overflow-wrap:anywhere]">{title}</h1>
                    </div>
                </div>
                {actions && <div data-page-header-actions className="flex w-full min-w-0 max-w-full flex-wrap items-center gap-3 xl:w-auto xl:max-w-[60%] xl:justify-end [&>*]:min-w-0 [&>*]:max-w-full [&>*]:flex-wrap [&_input]:max-w-full [&_select]:max-w-full">{actions}</div>}
            </div>
            {children && <div className="mt-4 min-w-0">{children}</div>}
        </header>
    );
}
