import { Settings2 } from 'lucide-react';
import InsightHero from '../InsightHero';

export default function SettingsLayout({
    children,
}: {
    activeTab?: string;
    onChangeTab?: (id: string) => void;
    children: React.ReactNode;
    userRole?: string;
}) {
    return (
        <div className="flex-1 flex flex-col min-h-0 bg-slate-50 dark:bg-slate-950">
            <div className="px-6 md:px-10 py-6 md:py-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shrink-0">
                <InsightHero
                    variant="light"
                    accent="sky"
                    icon={Settings2}
                    eyebrow="Settings"
                    title="Platform preferences"
                    className="!rounded-xl border-0 shadow-none bg-transparent px-0 py-0"
                />
            </div>

            <main className="flex-1 min-h-0 bg-slate-50 dark:bg-slate-950/80 p-6 md:p-10 overflow-auto">
                <div className="w-full max-w-none space-y-8 animate-fade-in">


                    {children}
                </div>
            </main>
        </div>
    );
}
